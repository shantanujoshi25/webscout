from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import requests
from bs4 import BeautifulSoup
import json
from openai import OpenAI
import time

app = Flask(__name__)
CORS(app)  

# Initialize OpenAI client
client = OpenAI(
    api_key="")

@app.route('/analyze', methods=['POST'])
def analyze_source():
    data = request.json
    source_code = data.get('source', '')
    url = data.get('url', '')
    
    # Parse the HTML
    soup = BeautifulSoup(source_code, 'html.parser')
    
    # Run traditional vulnerability checks
    vulnerabilities = []
    
    # Check for SSL/HTTPS
    ssl_vulnerabilities = check_ssl(url)
    vulnerabilities.extend(ssl_vulnerabilities)
    
    # Collect potential XSS and CSRF info for LLM analysis instead of immediate flagging
    input_elements, script_content = collect_xss_info(soup)
    forms_info = collect_csrf_info(soup)
    
    # Perform complete security analysis with LLM using collected context
    try:
        # Prepare detailed context for LLM analysis
        security_context = prepare_security_context(url, input_elements, script_content, forms_info)
        
        # Use LLM for comprehensive security analysis
        llm_vulnerabilities = analyze_with_llm(security_context)
        vulnerabilities.extend(llm_vulnerabilities)
        
    except Exception as e:
        print(f"Error in security analysis: {e}")
        # Fall back to basic detection if LLM analysis fails
        basic_xss = basic_xss_detection(soup)
        basic_csrf = detect_csrf_vulnerabilities(soup)
        vulnerabilities.extend(basic_xss)
        vulnerabilities.extend(basic_csrf)
    
    # Return results
    return jsonify({
        'url': url,
        'vulnerabilities': vulnerabilities
    })

def check_ssl(url):
    """Check if the website is using HTTPS"""
    vulnerabilities = []
    
    if url.startswith('http://'):
        vulnerabilities.append({
            'type': 'SSL',
            'severity': 'High',
            'location': url,
            'description': 'Website is not using HTTPS',
            'remediation': 'Implement HTTPS with a valid SSL certificate to encrypt data transmission'
        })
    elif url.startswith('https://'):
        # Check for HSTS header
        try:
            response = requests.head(url, timeout=5)
            if 'Strict-Transport-Security' not in response.headers:
                vulnerabilities.append({
                    'type': 'SSL',
                    'severity': 'Medium',
                    'location': url,
                    'description': 'HTTPS is enabled but missing HSTS header',
                    'remediation': 'Implement HTTP Strict Transport Security (HSTS) to prevent downgrade attacks'
                })
        except Exception as e:
            print(f"Error checking HSTS: {e}")
    
    return vulnerabilities

def collect_xss_info(soup):
    """Collect input elements and JavaScript content for XSS analysis"""
    
    # Find all input fields that could accept user input
    input_elements = []
    for input_el in soup.find_all(['input', 'textarea']):
        if input_el.get('type') not in ['hidden', 'button', 'submit']:
            # Collect information about the input
            input_info = {
                'element': str(input_el),
                'id': input_el.get('id', ''),
                'name': input_el.get('name', ''),
                'event_handlers': []
            }
            
            # Check for inline event handlers
            for attr in input_el.attrs:
                if attr.startswith('on'):  # e.g., onclick, onchange
                    input_info['event_handlers'].append(f"{attr}=\"{input_el[attr]}\"")
            
            input_elements.append(input_info)
    
    # Extract JavaScript content from the page
    script_content = []
    for script in soup.find_all('script'):
        if script.string:
            script_content.append(script.string)
        elif script.get('src'):
            script_content.append(f"External script: {script['src']}")
    
    return input_elements, script_content

def collect_csrf_info(soup):
    """Collect information about forms for CSRF analysis"""
    
    forms_info = []
    forms = soup.find_all('form')
    
    for form in forms:
        # Check for CSRF token
        has_csrf_token = False
        csrf_field_names = ['csrf', 'csrf_token', '_csrf', '_token', 'token']
        inputs = form.find_all('input', type='hidden')
        
        for input_field in inputs:
            name = input_field.get('name', '').lower()
            if any(token_name in name for token_name in csrf_field_names):
                has_csrf_token = True
                break
        
        # Collect information about the form
        form_info = {
            'element': str(form)[:300] + ('...' if len(str(form)) > 300 else ''),
            'action': form.get('action', ''),
            'method': form.get('method', 'get'),
            'has_csrf_token': has_csrf_token,
            'inputs': [str(i) for i in form.find_all('input')]
        }
        
        forms_info.append(form_info)
    
    return forms_info

def basic_xss_detection(soup):
    """Basic XSS vulnerability detection as fallback"""
    vulnerabilities = []
    
    # Find all input fields
    input_elements = soup.find_all(['input', 'textarea'])
    for input_el in input_elements:
        # Check for missing XSS protections
        if input_el.get('type') not in ['hidden', 'button', 'submit']:
            if not input_el.get('sanitized') and not input_el.get('data-xss-protection'):
                vulnerabilities.append({
                    'type': 'XSS',
                    'severity': 'Medium',
                    'location': str(input_el)[:100] + '...',
                    'description': 'Input field without explicit XSS protection found',
                    'remediation': 'Implement input sanitization and output encoding'
                })
    
    # Check for unsafe JavaScript
    script_tags = soup.find_all('script')
    for script in script_tags:
        if script.string and ('document.write' in script.string or 'innerHTML' in script.string):
            vulnerabilities.append({
                'type': 'XSS',
                'severity': 'High',
                'location': str(script)[:100] + '...',
                'description': 'Potentially unsafe JavaScript DOM manipulation',
                'remediation': 'Use safe DOM methods or frameworks with built-in XSS protection'
            })
    
    return vulnerabilities

def detect_csrf_vulnerabilities(soup):
    """Basic CSRF vulnerability detection"""
    vulnerabilities = []
    
    # Find all forms
    forms = soup.find_all('form')
    for form in forms:
        # Check for CSRF token
        has_csrf_token = False
        
        # Look for common CSRF token field names
        csrf_field_names = ['csrf', 'csrf_token', '_csrf', '_token', 'token']
        inputs = form.find_all('input', type='hidden')
        
        for input_field in inputs:
            name = input_field.get('name', '').lower()
            if any(token_name in name for token_name in csrf_field_names):
                has_csrf_token = True
                break
        
        if not has_csrf_token:
            vulnerabilities.append({
                'type': 'CSRF',
                'severity': 'High',
                'location': str(form)[:100] + '...',
                'description': 'Form without CSRF protection detected',
                'remediation': 'Implement CSRF tokens in all forms or use SameSite cookies'
            })
    
    return vulnerabilities

def prepare_security_context(url, input_elements, script_content, forms_info):
    """Prepare a comprehensive context for LLM security analysis"""
    
    context = {
        'url': url,
        'input_elements': input_elements,
        'script_content': script_content,
        'forms_info': forms_info
    }
    
    # Look for dangerous patterns in scripts
    dangerous_patterns = []
    for script in script_content:
        if script and isinstance(script, str):
            # Check for DOM manipulation methods
            if 'innerHTML' in script or 'outerHTML' in script:
                dangerous_patterns.append("DOM innerHTML/outerHTML usage detected")
            if 'document.write' in script:
                dangerous_patterns.append("document.write usage detected")
            if 'eval(' in script:
                dangerous_patterns.append("eval() usage detected")
            if '.href' in script or '.src' in script:
                dangerous_patterns.append("Dynamic attribute modification detected")
            if 'location' in script and ('=' in script or '.replace' in script):
                dangerous_patterns.append("URL/location manipulation detected")
                
            # Check for input value usage
            for input_info in input_elements:
                input_id = input_info.get('id', '')
                input_name = input_info.get('name', '')
                if input_id and input_id in script:
                    dangerous_patterns.append(f"Script accesses input (id={input_id})")
                if input_name and f"name='{input_name}'" in script or f'name="{input_name}"' in script:
                    dangerous_patterns.append(f"Script accesses input (name={input_name})")
    
    context['dangerous_patterns'] = dangerous_patterns
    
    # Check for presence of sanitization libraries
    sanitization_present = False
    for script in script_content:
        if script and isinstance(script, str):
            if any(lib in script for lib in ['DOMPurify', 'sanitize-html', 'xss', 'sanitize', 'escapeHTML']):
                sanitization_present = True
                break
    
    context['sanitization_present'] = sanitization_present
    
    return context

def analyze_with_llm(security_context):
    """Use LLM for comprehensive security analysis with enhanced DVWA detection"""
    
    # Format the context for the LLM
    url = security_context['url']
    input_elements = security_context['input_elements']
    script_content = security_context['script_content']
    forms_info = security_context['forms_info']
    dangerous_patterns = security_context['dangerous_patterns']
    sanitization_present = security_context['sanitization_present']
    
    # Collect full HTML structure data for better analysis
    full_html_structure = extract_full_page_structure(security_context)
    
    # Prepare input elements section with more detail
    input_elements_text = "Input Elements (detailed):\n"
    for i, input_el in enumerate(input_elements):
        input_elements_text += f"{i+1}. {input_el['element']}\n"
        input_elements_text += f"   ID: {input_el.get('id', 'None')}\n"
        input_elements_text += f"   Name: {input_el.get('name', 'None')}\n"
        if input_el['event_handlers']:
            input_elements_text += f"   Event handlers: {', '.join(input_el['event_handlers'])}\n"
    
    # Prepare script section with more context
    script_section = "JavaScript Analysis:\n"
    script_section += f"Total script tags: {len(script_content)}\n"
    
    # Extract interesting JavaScript patterns
    js_patterns = []
    for script in script_content:
        if script and isinstance(script, str):
            # Check for various patterns indicating potential vulnerabilities
            if 'document.location' in script or 'window.location' in script:
                js_patterns.append("- URL/location manipulation detected")
            if 'innerHTML' in script or 'outerHTML' in script:
                js_patterns.append("- DOM manipulation with innerHTML/outerHTML")
            if 'document.write' in script:
                js_patterns.append("- document.write usage detected")
            if 'eval(' in script:
                js_patterns.append("- eval() function usage detected")
            if 'ajax' in script.lower() or 'xhr' in script.lower() or 'fetch(' in script:
                js_patterns.append("- AJAX/Fetch API requests detected")
            if 'cookie' in script:
                js_patterns.append("- Cookie manipulation detected")
            
            # Include the most relevant scripts
            if any(pattern in script for pattern in ['innerHTML', 'document.write', 'eval(', 'location', 'cookie', 'ajax', '.value']):
                script_excerpt = script[:500] + "..." if len(script) > 500 else script
                script_section += f"\nInteresting script content:\n{script_excerpt}\n"
    
    if js_patterns:
        script_section += "\nDetected JavaScript Patterns:\n" + "\n".join(js_patterns)
    
    # Prepare forms section with detailed analysis
    forms_section = "Form Analysis:\n"
    
    # Look for suspicious form characteristics
    for i, form in enumerate(forms_info):
        forms_section += f"Form {i+1}:\n"
        forms_section += f"Action: {form['action']}\n"
        forms_section += f"Method: {form['method']}\n"
        forms_section += f"Has CSRF Token: {form['has_csrf_token']}\n"
        
        # Analyze form inputs for suspicious patterns
        input_analysis = []
        has_password = False
        has_file_upload = False
        has_hidden_inputs = False
        has_id_param = False
        
        for input_str in form['inputs']:
            if 'type="password"' in input_str:
                has_password = True
            if 'type="file"' in input_str:
                has_file_upload = True
            if 'type="hidden"' in input_str:
                has_hidden_inputs = True
            if 'name="id"' in input_str or 'name="user_id"' in input_str:
                has_id_param = True
        
        if has_password:
            input_analysis.append("- Contains password field (check for secure handling)")
        if has_file_upload:
            input_analysis.append("- Contains file upload (check for secure validation)")
        if has_id_param:
            input_analysis.append("- Contains ID parameter (potential SQL injection point)")
        
        forms_section += f"Form HTML: {form['element']}\n"
        if input_analysis:
            forms_section += "Suspicious patterns:\n" + "\n".join(input_analysis) + "\n"
        
        forms_section += "\n"
    
    # Analyze URL for vulnerability indicators
    url_analysis = "URL Analysis:\n"
    url_analysis += f"Full URL: {url}\n"
    
    # Check for common vulnerable parameters
    suspicious_params = {
        "id=": "Database record ID (potential SQL injection)",
        "file=": "File inclusion/path parameter (potential LFI/RFI)",
        "page=": "Page inclusion parameter (potential LFI)",
        "include=": "Include directive (potential LFI/RFI)",
        "path=": "File path parameter (potential path traversal)",
        "cmd=": "Command parameter (potential command injection)",
        "exec=": "Execution parameter (potential command injection)",
        "query=": "Database query parameter (potential SQL injection)",
        "user=": "User identifier (potential IDOR/SQLi)",
        "pass=": "Password in URL (credential exposure)",
        "debug=": "Debug flag (potential information disclosure)",
        "test=": "Test parameter (potential debug/backdoor)",
        "vuln=": "Vulnerability testing parameter (intentional vulnerability)"
    }
    
    found_suspicious = []
    for param, desc in suspicious_params.items():
        if param in url.lower():
            found_suspicious.append(f"- {param} : {desc}")
    
    if found_suspicious:
        url_analysis += "Suspicious URL parameters detected:\n" + "\n".join(found_suspicious) + "\n"
    
    # Check for common vulnerable URL patterns
    if "login" in url.lower():
        url_analysis += "- Login page detected (check authentication security)\n"
    if "admin" in url.lower():
        url_analysis += "- Admin functionality detected (check access controls)\n"
    if "upload" in url.lower():
        url_analysis += "- Upload functionality detected (check file validation)\n"
    if "search" in url.lower():
        url_analysis += "- Search functionality detected (check for SQLi/XSS)\n"
    
    # Fixed the string formatting issue
    sanitization_status = "Yes" if sanitization_present else "No"
    
    # Check for DVWA-specific indicators without hardcoding detection
    dvwa_indicators = ""
    if "dvwa" in url.lower() or "damn vulnerable" in full_html_structure.lower():
        dvwa_indicators = """
        NOTE: This appears to be DVWA (Damn Vulnerable Web Application) or similar intentionally vulnerable application.
        Such applications typically contain:
        1. SQL Injection vulnerabilities in forms with ID parameters
        2. XSS vulnerabilities in reflected parameters and stored inputs
        3. Command injection vulnerabilities in system-related functionality
        4. File inclusion/upload vulnerabilities
        5. CSRF vulnerabilities across most forms
        
        Pay special attention to these areas and assume minimal server-side protection.
        """
    
    # Craft a more comprehensive prompt for vulnerability analysis
    prompt = f"""
    I'm analyzing a web page for security vulnerabilities. I need a detailed security assessment focusing on ACTUAL vulnerabilities.
    
    {url_analysis}
    
    {input_elements_text}
    
    {script_section}
    
    {forms_section}
    
    Dangerous Patterns Detected:
    {', '.join(dangerous_patterns) if dangerous_patterns else "None specifically identified"}
    
    Sanitization libraries detected: {sanitization_status}
    
    {dvwa_indicators}
    
    TASK: Analyze the above information and identify security vulnerabilities.
    For vulnerability detection, make the following assumptions:
    1. Assume minimal server-side input validation unless evidence suggests otherwise
    2. Assume that user input from forms can flow to dangerous functions
    3. Assume that URL parameters without evidence of sanitization are vulnerable
    4. Consider the application context - if it appears to be a deliberately vulnerable application, assume less protection
    
    Analyze for these vulnerability types:
    
    1. XSS (Cross-site Scripting):
       - Input fields that might output to HTML without escaping
       - JavaScript that takes values from DOM and inserts them back
       - URL parameters that might be reflected in the page
    
    2. CSRF (Cross-site Request Forgery):
       - Forms without anti-CSRF tokens, especially state-changing ones
       - POST forms without proper protection
    
    3. SQL Injection:
       - Forms or URL parameters with names like "id", "user_id", "query"
       - Database-related functionality without evidence of parameterization
    
    4. Command Injection:
       - Inputs that might be passed to server commands (ping, lookup, etc.)
       - System-related functionality
    
    5. File Inclusion/Upload:
       - File upload forms without evidence of validation
       - URL parameters like "file", "page", "include"
    
    6. Authentication Weaknesses:
       - Login forms with weak security practices
       - Password storage or transmission issues
    
    Instead of requiring strong evidence, flag potential vulnerabilities with reasonable confidence.
    For each vulnerability, provide:
    - The vulnerability type
    - Severity (High/Medium/Low)
    - A clear description explaining why it's vulnerable
    - The specific location in the code/page
    - Remediation steps
    - Confidence level (Medium or High are acceptable)
    
    Return findings as JSON array:
    [
      {{"type": "...", "severity": "...", "description": "...", "location": "...", "remediation": "...", "confidence": "..."}}
    ]
    
    Even if evidence is not conclusive, include vulnerabilities with Medium confidence if they appear likely.
    """
    
    try:
        # Make the API call
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            temperature=0.1,
            messages=[
                {"role": "system", "content": "You are an expert in detecting web application vulnerabilities, specialized in analyzing DVWA and similar deliberately vulnerable applications. Return your analysis ONLY as a valid JSON array."},
                {"role": "user", "content": prompt}
            ]
        )
        
        result = response.choices[0].message.content
        print("LLM Response:", result)
        
        # Simple clean-up of the response before parsing
        result = result.strip()
        
        # Try to extract just the JSON part if there's extra text
        json_start = result.find('[')
        json_end = result.rfind(']') + 1
        
        if json_start >= 0 and json_end > json_start:
            result = result[json_start:json_end]
        
        # Remove any markdown code block formatting
        result = result.replace('```json', '').replace('```', '').strip()
        
        # Parse and clean the response
        try:
            parsed_response = json.loads(result)
            vulnerabilities = []
            
            # If it's a list, use it directly
            if isinstance(parsed_response, list):
                vulnerabilities = parsed_response
            
            # Filter and clean vulnerabilities
            cleaned_vulnerabilities = []
            for vuln in vulnerabilities:
                # Accept medium or high confidence
                confidence = vuln.get("confidence", "Low").lower()
                if confidence in ["medium", "high"]:
                    # Clean and standardize the vulnerability
                    cleaned_vuln = {
                        "type": vuln.get("type", "Unknown"),
                        "severity": vuln.get("severity", "Medium"),
                        "description": vuln.get("description", "Security issue detected"),
                        "location": vuln.get("location", "Unknown location"),
                        "remediation": vuln.get("remediation", vuln.get("fix", "Fix the identified security issue")),
                        "source": "ai_analysis"
                    }
                    cleaned_vulnerabilities.append(cleaned_vuln)
            
            return cleaned_vulnerabilities
            
        except json.JSONDecodeError as e:
            print(f"Failed to parse LLM response: {e}")
            print(f"Response content: {result}")
            # Return a generic vulnerability as fallback
            return [{
                "type": "Security Analysis",
                "severity": "Low",
                "description": "Could not complete advanced security analysis. Consider manual review.",
                "location": "N/A",
                "remediation": "Have a security expert manually review the page code."
            }]
    
    except Exception as e:
        print(f"Error in LLM analysis: {str(e)}")
        return []

def extract_full_page_structure(security_context):
    """Extract more complete page structure for analysis"""

    
    structure = ""
    

    # For now, return a simplified version based on available context
    if security_context.get('input_elements'):
        structure += "Page contains input elements\n"
    
    if security_context.get('forms_info'):
        structure += f"Page contains {len(security_context['forms_info'])} forms\n"
        
    if security_context.get('script_content'):
        structure += f"Page contains {len(security_context['script_content'])} script tags\n"
        
    # You could enhance this to provide more context about the page structure
    
    return structure

if __name__ == '__main__':
    app.run(debug=True, port=5000)
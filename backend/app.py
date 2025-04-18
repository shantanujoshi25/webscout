from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import requests
from bs4 import BeautifulSoup
from openai import OpenAI

app = Flask(__name__)
CORS(app)  


# openai.api_key = "your-openAI-key"
client = OpenAI(
        # api_key="your-api-key-here"  
)


@app.route('/analyze', methods=['POST'])
def analyze_source():
    
    data = request.json
    source_code = data.get('source', '')
    url = data.get('url', '')
    
    
    soup = BeautifulSoup(source_code, 'html.parser')
    
    # Perform vulnerability analysis
    xss_vulnerabilities = detect_xss_vulnerabilities(soup)
    csrf_vulnerabilities = detect_csrf_vulnerabilities(soup)
    
    # Enhance analysis with LLM
    all_vulnerabilities = xss_vulnerabilities + csrf_vulnerabilities
    if all_vulnerabilities:
        enhance_with_llm(all_vulnerabilities, source_code)
    
    # Return results
    return jsonify({
        'url': url,
        'vulnerabilities': all_vulnerabilities
    })

def detect_xss_vulnerabilities(soup):
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
    
    # Additional XSS checks would go here
    
    return vulnerabilities

def detect_csrf_vulnerabilities(soup):
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


def enhance_with_llm(vulnerabilities, source_code):
    """Use LLM to enhance vulnerability descriptions and remediation"""
    
    
    for i, vuln in enumerate(vulnerabilities):
        
        context = f"""
        Vulnerability type: {vuln['type']}
        Location: {vuln['location']}
        Description: {vuln['description']}
        
        Based on this information and your security expertise, provide:
        1. A more detailed description of this vulnerability
        2. Specific remediation steps for this vulnerability
        
        keep it concise.
        """
        
        try:
           
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                temperature = 0.1,
                messages=[
                    {"role": "system", "content": "You are a web security expert analyzing code for vulnerabilities."},
                    {"role": "user", "content": context}
                ]
            )
            
           
            result = response.choices[0].message.content
            
            
            sections = result.split('\n\n')
            if len(sections) >= 2:
                vulnerabilities[i]['description'] = sections[0].strip()
                vulnerabilities[i]['remediation'] = sections[1].strip()
        except Exception as e:
            print(f"Error calling LLM API: {e}")
            # Keep original description and remediation if LLM enhancement fails
            
    return vulnerabilities

# def enhance_with_llm(vulnerabilities, source_code):
#     """Use LLM to enhance vulnerability descriptions and remediation"""
#     for i, vuln in enumerate(vulnerabilities):
        
#         context = f"""
#         Vulnerability type: {vuln['type']}
#         Location: {vuln['location']}
#         Description: {vuln['description']}
        
#         Based on this information and your security expertise, provide:
#         1. A more detailed description of this vulnerability
#         2. Specific remediation steps for this vulnerability
#         """
        
#         try:
            
#             response = openai.ChatCompletion.create(
#                 model="gpt-3.5-turbo",
#                 messages=[
#                     {"role": "system", "content": "You are a web security expert analyzing code for vulnerabilities."},
#                     {"role": "user", "content": context}
#                 ]
#             )
            
            
#             result = response.choices[0].message.content
            
            
#             sections = result.split('\n\n')
#             if len(sections) >= 2:
#                 vulnerabilities[i]['description'] = sections[0].strip()
#                 vulnerabilities[i]['remediation'] = sections[1].strip()
#         except Exception as e:
#             print(f"Error calling LLM API: {e}")
#             # Keep original description and remediation if LLM enhancement fails

if __name__ == '__main__':
    app.run(debug=True, port=5000)
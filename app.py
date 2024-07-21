from flask import Flask, request, render_template, jsonify, make_response
import requests
import pdfkit
import os

app = Flask(__name__)

# Caminho para o executável wkhtmltopdf
path_wkhtmltopdf = os.path.join('C:', os.sep, 'Program Files', 'wkhtmltopdf', 'bin', 'wkhtmltopdf.exe')
pdfkit_config = pdfkit.configuration(wkhtmltopdf=path_wkhtmltopdf)

def analyze_cookie_security(cookie):
    analysis = []

    if cookie['httpOnly'] == 'No':
     analysis.append("Risks without HttpOnly flag: "
                    "1. Cross-Site Scripting (XSS): Vulnerable to malicious scripts that can steal cookies. "
                    "2. Unauthorized access to sensitive information: Cookies can be accessed by malicious scripts. "
                    "3. Increased risk in social engineering attacks: Cookies can be used in social engineering attacks. "
                    "4. Session Hijacking: Risk of session hijacking.")

    if cookie['secure'] == 'No':
      analysis.append("Risks without Secure flag: "
                    "1. Data interception: Cookies can be intercepted in insecure connections. "
                    "2. Cookie theft: Risk of stealing sensitive information in insecure connections. "
                    "3. Man-in-the-Middle Attacks (MitM): Vulnerable to MitM attacks. "
                    "4. Data integrity risks: Cookies can be modified during transmission.")


    if not analysis:
        return "Secure: Cookie with the Secure and HttpOnly flags enabled."
    else:
        return " ".join(analysis)

def get_cookie_details(domain):
    try:
        response = requests.get(f'http://{domain}')
        cookies = response.cookies

        cookie_list = []
        for cookie in cookies:
            cookie_details = {
                'name': cookie.name,
                'value': cookie.value,
                'domain': cookie.domain,
                'path': cookie.path,
                'expires': cookie.expires if cookie.expires else 'N/A',
                'secure': 'yes' if cookie.secure else 'No',
                'httpOnly': 'yes' if cookie.has_nonstandard_attr('HttpOnly') else 'No'
            }
            cookie_details['detailed_analysis'] = analyze_cookie_security(cookie_details)
            cookie_list.append(cookie_details)

        return cookie_list
    except Exception as e:
        return []

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/check_cookie', methods=['POST'])
def check_cookie():
    domain = request.form.get('domain', '')
    cookie_data = get_cookie_details(domain)
    return jsonify(cookie_data)

@app.route('/detailed_report', methods=['GET'])
def detailed_report():
    domain = request.args.get('domain', '')
    cookie_data = get_cookie_details(domain)
    return render_template('detailed_report.html', domain=domain, cookies=cookie_data)

@app.route('/download_report', methods=['GET'])
def download_report():
    domain = request.args.get('domain', '')
    cookie_data = get_cookie_details(domain)
    rendered = render_template('detailed_report.html', domain=domain, cookies=cookie_data)
    pdf = pdfkit.from_string(rendered, False, configuration=pdfkit_config)

    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=report.pdf'
    return response

if __name__ == '__main__':
    app.run(debug=True)

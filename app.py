from flask import Flask, render_template_string, request
import requests
import validators

app = Flask(__name__)

# Fungsi untuk mengecek apakah link aman menggunakan Google Safe Browsing API
def check_link_safety(api_key, url_to_check):
    safe_browsing_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    
    payload = {
        "client": {
            "clientId": "web_app",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url_to_check}]
        }
    }
    
    params = {"key": api_key}
    response = requests.post(safe_browsing_url, json=payload, params=params)

    # Logging untuk memeriksa respons
    print(f"Response Code: {response.status_code}")
    print(f"Response Text: {response.text}")

    if response.status_code == 200:
        result = response.json()
        if "matches" in result:
            return False  # URL tidak aman
        else:
            return True   # URL aman
    else:
        return None      # Terjadi kesalahan

@app.route('/', methods=['GET', 'POST'])
def index():
    api_key = "AIzaSyDAxlSl0EcRm-wljz1ynZ4I471mZyBZ0hY"  # Ganti dengan API key kamu
    result = None
    url = None
    
    if request.method == 'POST':
        url = request.form.get('url')  # Mengambil input URL dari form
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        if url and validators.url(url):
            is_safe = check_link_safety(api_key, url)
            if is_safe is None:
                result = "Error saat memeriksa URL"
            elif is_safe:
                result = "URL aman!"
            else:
                result = "URL tidak aman!"
        else:
            result = "URL tidak valid."

    # Render HTML langsung dari string
    html_content = f"""
    <!doctype html>
    <html>
    <head>
        <title>URL Checker</title>
    </head>
    <body>
        <h1>URL Checker</h1>
        <form method="post">
            <input type="text" name="url" placeholder="Masukkan URL" required>
            <button type="submit">Periksa</button>
        </form>
        <h2>Hasil: {result}</h2>
    </body>
    </html>
    """
    return render_template_string(html_content)

if __name__ == '__main__':
    app.run(debug=True)

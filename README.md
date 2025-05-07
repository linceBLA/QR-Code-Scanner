# QR Code Security Scanner using Virus Total

In today’s digital world, QR codes are commonly used but can sometimes lead to malicious websites. To address this security concern, I developed a web-based solution that combines a Python script with an HTML front-end, hosted on PythonAnywhere. This tool allows users to scan QR codes directly through the web page. Upon scanning, the embedded URL is checked for safety using the VirusTotal API, which I access through my personal account. If the URL is deemed safe, it is opened in the browser. However, if the URL is flagged as potentially malicious, the page prevents access and alerts the user, ensuring that the scanned link is verified before being accessed.

You can easily set up your own QR Code Security Scanner by using the Python script and HTML file I’ve provided. To get started, you'll need to:

#### 1. Create a free account on the <a href="https://www.virustotal.com/gui/sign-in">VirusTotal API<a/> and obtain your personal API key.

#### 2. Sign up for a free account on <a href="https://www.pythonanywhere.com/registration/register/beginner/">PythonAnywhere<a/> and upload my two scripts: <a href="https://github.com/linceBLA/Python-Scripts/blob/main/QRCODE-Scan_flask_app.py">QRCODE-Scan_flask_app.py<a/> and <a href="https://github.com/linceBLA/Python-Scripts/blob/main/QRCODE-Scan_index.html">QRCODE-Scan_index.html<a/>.

#### 3. In the QRCODE-Scan_flask_app.py script, make sure to replace the placeholder 'my API key' with your actual VirusTotal API key.

#### 4. Allow your browser to access the camera when prompted for QR code scanning. I recommend setting it to manually request permission each time for added control over security.

The HTML file is quite basic, designed with functionality in mind rather than aesthetics. Feel free to customize and enhance the HTML to suit your needs. My primary goal is to provide a working tool, not to sell or promote it—so make it your own!


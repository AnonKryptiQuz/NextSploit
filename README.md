# **NextSploit: Next.js CVE-2025-29927 Scanner & Exploiter**

**NextSploit** is a command-line tool designed to detect and exploit **CVE-2025-29927**, a security flaw in Next.js. The tool first identifies if a target website is running Next.js and determines whether its version falls within the vulnerable range. If the website is confirmed to be vulnerable, the tool **automatically attempts to exploit the issue** by bypassing middleware protections, potentially granting unauthorized access to restricted pages.


## **Features**

- **Automated Next.js Version Detection**: Uses Wappalyzer to check if the target website runs Next.js and retrieves its version.
- **Vulnerability Assessment**: Determines if the detected version is within the known vulnerable range.
- **Middleware Exploitation Test**: Attempts to exploit the **CVE-2025-29927** vulnerability using middleware headers.
- **Automated Chrome Browser Launch**: Opens the target URL with necessary headers preconfigured to bypass authentication (if vulnerable).

## **Prerequisites**

- **Python 3.7+**
- **Selenium**
- **ChromeDriver**
- **GeckoDriver**
- **Wappalyzer CLI**
- **Google Chrome**

## **Installation**

1. **Clone the repository:**

   ```bash
   git clone https://github.com/AnonKryptiQuz/NextSploit.git
   cd NextSploit
   ```

2. **Install required Python packages:**

   ```bash
   pip install -r requirements.txt
   ```

   Ensure that `requirements.txt` contains the following:

   ```
   wappalyzer
   requests
   colorama
   selenium
   ```

3. **Download ChromeDriver**

   Ensure that ChromeDriver is installed and accessible. You can install it manually or use `webdriver_manager` to handle automatic driver installation.

   - [ChromeDriver Download](https://developer.chrome.com/docs/chromedriver/downloads)

4. **GeckoDriver**

   Ensure that GeckoDriver is installed and accessible.

## **Usage**

1. **Run the tool:**

   ```bash
   python NextSploit.py
   ```

2. **Follow the prompts:**
   - Enter the URL of the target website.
   - Choose a scan type (`Fast`, `Balanced`, or `Full`).
   - The tool will analyze the website and check if it's vulnerable.

3. **Testing for Vulnerability:**
   - If the tool detects Next.js, it will check its version.
   - If the version is within the vulnerable range, the tool will attempt to bypass middleware protections.

4. **Launching Browser for Exploitation:**
   - If the website is vulnerable, the tool will launch Chrome with a preconfigured request to bypass login protections.
   - You can manually inspect the result.

## **Learn More**

To understand the details of **CVE-2025-29927**, its impact, and potential mitigations, visit the official NIST National Vulnerability Database (NVD) page:

🔗 **[CVE-2025-29927 - NVD Details](https://nvd.nist.gov/vuln/detail/CVE-2025-29927)**

This page includes an in-depth analysis, severity rating, and any patches or fixes provided by the Next.js team.

## **Disclaimer**

- **Educational Purposes Only**: This tool is intended solely for security research, ethical hacking, and educational purposes. The user is responsible for ensuring compliance with local laws and regulations.
- **No Guarantee of Accuracy**: NextSploit on external tools like Wappalyzer, which may not always detect Next.js versions accurately. Results should be manually verified.

## **Author**

**Created by:** [AnonKryptiQuz](https://AnonKryptiQuz.github.io/)

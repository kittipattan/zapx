# ZAPx: Extending OWASP ZAP for Enhanced Web Vulnerability Detection and AI-Powered Remediation

Web applications face a growing size of security threats, including vulnerabilities from automated attacks and client-side code weaknesses. Automated threats, such as web scraping, brute force, and flood requests, often exploit the absence of robust defenses like rate limiting or CAPTCHA. Simultaneously, insecure client-side code can expose sensitive information, including API keys and access tokens, leading to unauthorized access and data breaches. Traditional tools like OWASP Zed Attack Proxy (ZAP) offer powerful detection mechanisms but lack comprehensive solutions for these challenges. To address these limitations, we propose an extension to OWASP ZAP that integrates generative AI for automated vulnerability remediation and enhances detection of automated attack vulnerabilities and client-side code risks. Our approach incorporates active and passive scanning scripts tailored to detect weaknesses exploited by automation tools and client-side security flaws. A standalone script powered by generative AI generates practical, context-specific remediation plans for mitigating vulnerabilities, reducing the time and effort required for manual mitigation. The proposed approach connects the gap between detection and actionable remediation, providing a comprehensive tool for addressing modern web application security challenges.

## How to integrate and run scripts in ZAP

### 1. Active Rules

Active Rules are used for actively testing vulnerabilities by modifying and sending requests to the target. We use Active Rules script for Bot defense mechanism detection

#### Steps to Add Active Rules:

1. Go to the "Scripts" tab in the top left panel. If cannot find, click on the "+" and click "Scripts"
2. In the left panel, click the folder icon (Load Script ...).
3. Find and select [bot_defense_detection.js](./script/bot_defense_detection.js)
4. In the dialog box:
    - Script Engine: `ECMAScript: Graal.js`
    - Type: `Active Rules`
5. Click "Save"
6. Enable the script by right click the script name and click "Enable Script(s)", or click on the top left icon (Enable Script) of the Script Console
7. Run an active scan on the target. ZAP will execute custom active rule during the scan

### 2. Passive Rules

Passive Rules are used to analyze traffic and detect issues without altering requests or responses. We use Passive Rules script for Client-side code vulnerabilities detection

#### Steps to Add Passive Rules:

Similar to how we add Active Rules except:

3. Find and select [client_vuln_detection.py](./script/client_vuln_detection.py)
4. In the dialog box:
    - Script Engine: `python: jython`
    - Type: `Passive Rules`
7. When passive scanning is performed (e.g., when ZAP proxies traffic), the rule will automatically execute

### 3. Stand Alone

Standalone Scripts are custom scripts that can be run manually to perform specific tasks, such as custom automation or API interactions. We use Stand Alone script for Remediation plan generation by generative AI

#### Steps to Add Stand Alone:

Similar to how to add Active Rules except:

3. Find and select [remplan_gen.js](./script/remplan_gen.js)
4. In the dialog box:
    - Script Engine: `ECMAScript: Graal.js`
    - Type: `Stand Alone`
5. Click "Save"
6. Specify the `zapApiKey` and `perplexityApiKey`
    - Specify technology stack `techStack` of the target application for more precise and easier to implement mitigation strategies.
    - Specify the output path `outputPath` of the generated report
7. To execute the standalone script, click "Run" button at the top panel
8. The generated report is saved at the specified output path

### Alternative

If you don't want to import the script, you can copy and paste the code instead

#### Steps:

1. Go to the "Scripts" tab in the top left panel. If cannot find, click on the "+" and click "Scripts"
2. In the left panel, click the new script icon (New Script ...).
3. In the dialog box:
    - Script Name: `<anything>`
    - Type: `<type_of_script>` -- `Active Rules`, `Passive Rules`, or `Stand Alone`
    - Script Engine: `<engine>` -- `ECMAScript: Graal.js` or `python: jython`
4. Click "Save"
5. Copy the code from one of our scripts and Paste it into the Script Console

## How to simulated web application

### 1. Install Node.js and npm

- Ensure that Node.js (with npm) is installed on your system.
- You can download the latest version of Node.js from [Node.js official site](https://nodejs.org/).

To check if Node.js is installed, run:

```bash
node -v
npm -v
```

---

### 2. Install MySQL

- Install MySQL on your system. You can download it from [MySQL official site](https://dev.mysql.com/downloads/).
- During installation, set a root password for the MySQL server.

To check if MySQL is installed, run:

```bash
mysql --version
```

---

### 3. Set Up the Database

#### a. Start the MySQL Server

- Ensure that the MySQL server is running. Start the service using the terminal or your system's service manager.

#### b. Login to MySQL

Run:

```bash
mysql -u root -p
```

Enter the root password you set during installation.

#### c. Create a Database

Create a database and a user for the application:

```sql
CREATE DATABASE vulnerable_app;

CREATE USER 'vulnerable_user'@'localhost' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON vulnerable_app.* TO 'vulnerable_user'@'localhost';
FLUSH PRIVILEGES;
```

---

### 4. Install Dependencies

- Navigate to the project directory in your terminal and install all required Node.js dependencies listed in `package.json`:

```bash
npm install
```

---

### 5. Run the Application

- Navigate to the directory of the application that you want to run
    - `vulnerable` for vulnerable web application
    - `patched` for patched web application
- Or type the relative/absolute path if you want
- Start the application using:

```bash
node <application_name.js>
# For example:
node app.js
node app_p.js
node ./vulnerable/app.js
```

---

### 6. Access the Application

- Open your browser and go to `http://localhost:3000`.
- You can now interact with the app and test its various functionalities.

---

### 7. Test Vulnerabilities

- Visit specific endpoints like `/xss-reflected`, `/sqli`, etc., to examine their behavior.
- Ensure you're using a secure environment (e.g., local machine) to avoid unintended risks.

---

## Contributor

- [archawitch](https://github.com/archawitch)
- [kittipattan](https://github.com/kittipattan)
- [PakaponRattanasrisuk](https://github.com/PakaponRattanasrisuk)

## Related courses

CSS453 Cyber Crimes and Digital Forensics at Sirindhorn International Institute of Technology (SIIT), Curriculum year 2021
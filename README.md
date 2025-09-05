

# Cybersecurity Internship – OWASP Juice Shop Project

**Name:** Abdul Basit Rizwan
**ID:** DHC-251
**Field:** Cybersecurity

This repository documents my work during a **Cybersecurity Internship**, where I was tasked with analyzing, securing, and testing vulnerabilities in the **OWASP Juice Shop application**.
The project was divided into **three major tasks** covering security assessment, mitigation, and reporting.

---

## 🔒 Internship Task Overview

### **Task 1 – Security Assessment**

* **Objective:** Analyze a web application for vulnerabilities.

* **Activities Performed:**

  * Set up OWASP Juice Shop locally (`npm install`, `npm start`).
  * Performed **OWASP ZAP scans** (spidering, active scans, alerts review).
  * Tested for **XSS** using `<script>alert('XSS')</script>` and `<iframe>` payloads.
  * Performed **SQL Injection** login bypass (`' OR 1=1--`).
  * Documented vulnerabilities: XSS, SQL Injection, weak headers, cookie issues, CSRF absence, security misconfigurations.

* **Outcome:**
  Identified multiple critical vulnerabilities (SQL Injection, XSS, CSRF, misconfigurations).
  Provided remediation steps such as **prepared statements, CSP headers, secure cookies, and anti-CSRF tokens**.

---

### **Task 2 – Implementing Security Measures**

* **Objective:** Strengthen the web application against discovered vulnerabilities.

* **Activities Performed:**

  * **Input Validation & Sanitization:** Used `validator` to sanitize emails and prevent malicious input.
  * **Password Hashing:** Implemented `bcrypt` for secure password storage.
  * **Authentication:** Added **JWT (JSON Web Token)** authentication for stateless, scalable login.
  * **Security Headers:** Used `Helmet.js` to set headers (e.g., `X-Frame-Options`, `X-Content-Type-Options`).
  * **Logging:** Integrated **Winston** logger for monitoring and auditing.

* **Outcome:**
  Hardened the application against injection attacks, secured user credentials, added token-based authentication, and applied essential HTTP headers.

---

### **Task 3 – Advanced Security & Reporting**

* **Objective:** Perform penetration testing, advanced security practices, and final reporting.

* **Activities Performed:**

  * Conducted **basic penetration testing** for SQL injection and XSS.
  * Verified application behavior under malicious login attempts.
  * Checked **HTTPS vs HTTP** usage (identified local app using HTTP).
  * Implemented **logging with Winston** for activity tracking.
  * Prepared a **security checklist**: input validation, HTTPS enforcement, password hashing, and secure headers.

* **Outcome:**
  Successfully demonstrated attacks (SQLi), verified protections, and compiled a **final security checklist** for best practices.

---

## 📚 Key Learnings

* How to **assess vulnerabilities** using OWASP ZAP, manual XSS & SQLi testing.
* Importance of **input validation, sanitization, and password hashing**.
* Implementing **JWT authentication** for secure, stateless login.
* Configuring **Helmet.js** and **Winston logging** for enhanced security.
* Documenting vulnerabilities and preparing professional **security reports**.

---

## 📂 Repository Contents

Task-1-Internship-report.pdf
Task-2-Internship-report.pdf
Task-3-Internship-report.pdf
* **Source Code** – OWASP Juice Shop application (modified during tasks).

---

## ✅ Conclusion

Through this internship, I gained hands-on experience in:

* Identifying and exploiting vulnerabilities.
* Applying security patches and mitigations.
* Following best practices in **web application security**.

This project enhanced my skills in **practical cybersecurity testing, remediation, and documentation** using OWASP Juice Shop as a training platform.

---


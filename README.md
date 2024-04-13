# DC1 Capture The Flag (CTF) Challenge Walkthrough (PTES Standard)

## Overview

This document provides a structured walkthrough of the DC1 CTF challenge based on the Penetration Testing Execution Standard (PTES). This challenge is hosted on Vulnhub and is designed to simulate real-world penetration testing scenarios to enhance network security skills.

## Table of Contents

1. Pre-engagement Interactions
2. Intelligence Gathering
3. Threat Modeling
4. Vulnerability Analysis
5. Exploitation
6. Post Exploitation
7. Reporting
8. Lessons Learned

## 1. Pre-engagement Interactions

### Objective

The goal of this exercise was to simulate an authorized penetration test to gain root access to the server and retrieve the root flag.

## 2. Intelligence Gathering

### Tools and Commands

- **Nmap**:
  - Command: `nmap -sV -sC 10.0.2.XX`
  - Purpose: To perform port scanning and service enumeration on the target IP `10.0.2.XX`.

### Key Findings

The Nmap scan revealed significant services running on the target system:

- **SSH (Secure Shell)**:
  - **Port**: 22/tcp
  - **Service Version**: OpenSSH 6.0p1 Debian 4+deb7u7, known for that may allow unauthorized access.
  - **Host Keys**:
    - DSA, RSA, ECDSA - keys exposed here are critical for verifying host identity and should be regularly rotated.

- **HTTP (Hypertext Transfer Protocol)**:
  - **Port**: 80/tcp
  - **Web Server**: Apache httpd 2.2.22 running Drupal 7, a configuration known for its susceptibility to [specific exploits](https://www.drupal.org/sa-core-2019-002).
  - **robots.txt Entries**: Lists paths that should not be crawled by search engines, potentially revealing sensitive areas of the site.

- **RPC (Remote Procedure Call)**:
  - Services running over multiple ports, exposing essential services to the network which can be a vector for [Distributed Denial of Service (DDoS) attacks](https://www.us-cert.gov/ncas/alerts/TA14-353A).

### Analysis

This section evaluates the implications of the identified services and configurations:

- **SSH Vulnerabilities**: Given the outdated version of OpenSSH, upgrading to a more secure version is imperative to prevent potential breaches.
- **Drupal Risks**: The Drupal instance should be updated or patched to mitigate known vulnerabilities, particularly SQL Injection and XSS, which are prevalent in older versions.
- **RPC Exposure**: Restricting RPC to internal networks or implementing strict access controls can reduce the risk of external attacks.


### Analysis

- **SSH Service**: The presence of an older version of OpenSSH (6.0p1) suggests potential vulnerabilities related to SSH that could be exploited.
- **Drupal Installation**: The Drupal 7 installation might be vulnerable depending on the patch level and the plugins installed. Known vulnerabilities in Drupal 7 include SQL Injection, Cross-Site Scripting (XSS), and Remote Code Execution (RCE), making it a prime target for further exploitation.
- **RPC Services**: The open RPC services suggest that the system may be using network file systems or other remote services that can be probed for further vulnerabilities.

This comprehensive mapping of the network services provides multiple vectors for potential exploitation, which will be prioritized in the Threat Modeling phase.


## 3. Threat Modeling

### Identified Services and System Components

Using the intelligence gathered from the Nmap and DIRB scans, we've identified several critical services and components that could potentially be exploited. These include:

- **SSH Service on Port 22**: Running an older version of OpenSSH, which might be susceptible to various exploits depending on configuration and patch level.
- **HTTP Service on Port 80**: Hosting a Drupal 7 site, which has a history of critical vulnerabilities that could be exploited if patches and updates are not applied.
- **RPC Service on Port 111**: Exposes several RPC-related services, which could be vulnerable to unauthorized access or denial of service attacks.

### Potential Threat Vectors

Based on the system's exposed services and the sensitive directories identified, the following threat vectors emerge:

1. **Web Application Attacks**:
   - **SQL Injection and XSS**: Given Drupal’s past vulnerabilities and the presence of numerous interactive endpoints (`/user`, `/node`, etc.), these common web attacks are a primary concern.
   - **Misconfigured Server Files**: Accessible files like `web.config` (misplaced in an Apache environment) and `xmlrpc.php` could provide vectors for information disclosure or remote code execution.

2. **Service Specific Attacks**:
   - **SSH Brute Force**: Older OpenSSH versions might be vulnerable to brute force attacks or exploits targeting specific cryptographic weaknesses.
   - **RPC Exploitation**: Misconfigurations in RPC could allow unauthorized access or privilege escalation.

3. **Unauthorized Access via Misconfigured Directories and Files**:
   - **Administrative Interfaces**: The 403 responses for `/admin`, `/batch`, and other admin-related paths suggest that these areas are protected but might still be accessible through credential stuffing or session hijacking.
   - **Sensitive Directories**: Directories like `/includes/`, `/misc/`, and `/modules/` contain operational scripts and configurations that, if improperly secured, could be exploited to gain further system access.

### Threat Actor Profiling

The threats identified would likely be most appealing to:
- **Script Kiddies**: Attempting common exploits found in online forums against known vulnerabilities in Drupal.
- **Organized Hackers**: Interested in exploiting more complex vulnerabilities or conducting coordinated attacks that might combine several vulnerabilities.
- **Insider Threats**: Such as disgruntled employees who could exploit internal knowledge of the network for unauthorized access or data exfiltration.

### Risk Assessment

Given the identified vulnerabilities and potential threats, the highest risks to the system appear to be:
- **Web Application Vulnerabilities**: Especially if the Drupal installation is outdated, which could lead to full system compromise.
- **Exposed Administrative Tools and Directories**: Which, if accessed, could allow changes to site configuration and data.

### Prioritization of Threats

The most critical threats to address are:
1. **Drupal vulnerabilities**: Due to the high potential for widespread damage or unauthorized access, particularly SQL Injection and XSS.
2. **SSH vulnerabilities**: Given the foundational security role SSH plays in system management.
3. **Misconfigured and sensitive directories**: Which could leak sensitive information or provide further access vectors.

This expanded threat modeling exercise provides a clearer picture of potential vulnerabilities and aligns with our overall penetration testing strategy. By understanding and prioritizing these threats, we can tailor our testing efforts to be both efficient and effective.


## 4. Vulnerability Analysis

### Directory Enumeration

#### Tool and Command

- **DIRB**:
  - Command: `dirb http://10.0.2.15 /usr/share/dirb/wordlists/common.txt`
  - Purpose: To discover hidden or unlinked directories and files on the web server that might contain sensitive information or be vulnerable to exploitation.

#### Key Findings

DIRB scan results highlighted several interesting directories and files, indicating possible vectors for further exploitation:

- **Accessible Resources**:
  - `[200] /0`: Possible default or misconfigured file.
  - `[200] /index.php`: Standard entry point for Drupal.
  - `[200] /LICENSE`: Often overlooked, could contain useful legal information.
  - `[200] /node`: Common Drupal endpoint, potential for node enumeration or manipulation.
  - `[200] /README`: Could provide system or application details.
  - `[200] /robots`: Reveals the `robots.txt` file which includes paths that should not be indexed by search engines.
  - `[200] /robots.txt`: Direct access to disallowed paths.
  - `[200] /user`: Standard Drupal user login or registration page.
  - `[200] /web.config`: Configuration file for web applications on IIS servers, misconfigured here for Apache.
  - `[200] /xmlrpc.php`: Endpoint for XML-RPC; historically a target for exploits.

- **Forbidden Directories [403]**:
  - `/admin`, `/Admin`, `/ADMIN`: Suggests administrative interfaces are present but restricted.
  - `/batch`, `/cgi-bin/`, `/install.mysql`, `/install.pgsql`, `/search`, `/Search`, `/server-status`: Indicate potential sensitive areas protected by server configuration.
  
- **Directories of Interest**:
  - `/includes/`: Typically contains core PHP files for Drupal, might be exploitable if misconfigured.
  - `/misc/`: Contains miscellaneous scripts and files which might include utilities like AJAX handlers or jQuery libraries.
  - `/modules/`: Core or custom Drupal modules, potential for module-specific vulnerabilities.
  - `/profiles/`: Drupal installation profiles.
  - `/scripts/`: Can contain executable scripts which might be vulnerable to unauthorized access or execution.
  - `/sites/`: Contains configurations for different hosted sites, could expose database settings if misconfigured.
  - `/themes/`: Themes can contain PHP files that might be exploitable.
  
- **Miscellaneous Findings in `/misc/` Directory**:
  - Many accessible files (`ajax`, `batch`, `collapse`, `configure`, `drupal`, etc.) providing functionalities like AJAX responses or configuration interfaces, which could be abused if they handle user input unsafely.

### Analysis

- The presence of multiple `[403] Forbidden` responses for directories typically associated with administrative functions (`/admin`, `/batch`, etc.) suggests these paths are protected by access controls, which might be bypassed with proper credentials or through security misconfigurations.
- The discovery of operational files and scripts (`/misc/jquery`, `/xmlrpc.php`, etc.) underlines the need for further investigation to determine if these files are exposed to exploit vulnerabilities such as SQL Injection, Local File Inclusion, or Remote Code Execution.

This enumeration phase provides crucial insights into the target's configuration and layout, paving the way for targeted attacks in the exploitation phase.

### 5. Exploitation

### Exploitation Details

Using Metasploit's Drupal Drupalgeddon2 exploit, we successfully gained access to the target system. This exploit leverages a well-known vulnerability in Drupal's Form API to execute arbitrary PHP code.

#### Tool and Command

- **Metasploit Usage**:
  - Command: `use exploit/unix/webapp/drupal_drupalgeddon2`
  - Purpose: To exploit known vulnerabilities in Drupal's Form API to execute arbitrary PHP code.
  - Execution: Successfully initiated a `meterpreter` session, providing a remote shell as the `www-data` user.

- **Python Upgrade**:
  - Command: `python -c 'import pty; pty.spawn("/bin/bash")'`
  - Purpose: To upgrade the Meterpreter shell to a more stable bash shell.

## 6. Post Exploitation

### Initial System Survey

- **Command Execution**:
  - Commands: 
    ```bash
    ls  # Listed directory contents
    whoami  # Confirmed user as 'www-data'
    ```
  - Findings: Initial directory listing provided insight into the web server's file structure; user confirmation established limited privileges.

### Further Exploration and Privilege Escalation

- **Directory and File Exploration**:
  - Commands:
    ```bash
    cd /home
    ls  # Explored user directories
    cd flag4
    cat flag4.txt  # Read contents of flag4.txt
    ```
  - Result: Discovered additional flags and hints for further actions.

- **Privilege Escalation Attempt**:
  - Command: `find DC1 -exec "/bin/sh" \;`
  - Result: Unexpectedly gained root access due to misconfigured system permissions.

## 7. Capturing the Flag

### Flag Retrieval and System Mastery

- **Root Access Confirmation and Exploration**:
  - Commands:
    ```bash
    whoami  # Confirmed root access
    cd /root
    ls  # Listed files in root directory
    cat thefinalflag.txt  # Displayed final flag
    ```
  - Insights: Full system access achieved; final flag indicated successful completion of objectives.

## 8. Lessons Learned

## 8. Recommendations

### Strengthening System Security

Given the vulnerabilities exploited and observations made during the penetration test, the following recommendations are aimed at enhancing the security of the system to prevent similar breaches in the future:

- **Regular Updates and Patch Management**:
  - Ensure that all software, especially critical components like the Drupal CMS and the server's operating system, are kept up-to-date with the latest security patches. This includes updates to the PHP environment, Apache, and any other associated software.
  - Regularly check for and apply updates for all plugins and themes used by Drupal to prevent vulnerabilities like those seen in Drupalgeddon.

- **Enhanced Monitoring and Logging**:
  - Implement comprehensive monitoring and logging of all system and network activities to detect and respond to unauthorized access attempts or suspicious activities quickly. Use tools that can provide real-time alerts and automate responses to common threats.
  - Ensure logs are protected against tampering and stored in a secure location.

- **Web Server Configuration and Hardening**:
  - Review and tighten web server configurations to limit the server's exposure to attacks. This includes disabling unnecessary services, applying the principle of least privilege to service accounts, and using security modules such as ModSecurity for Apache.
  - Ensure that `web.config`, `.htaccess`, and other configuration files are properly set up to prevent unauthorized access and disclosure of sensitive information.

- **Secure SSH Access**:
  - Use public key authentication for SSH rather than passwords to minimize the risk of brute-force attacks.
  - Consider changing the default SSH port to reduce the risk of automated attacks and employ rate limiting and connection throttling to defend against brute-force attempts.

- **Drupal Security Practices**:
  - Regularly review and configure Drupal’s user permissions and access control settings to ensure that only authorized users have administrative privileges.
  - Use Drupal security modules such as "Paranoia" and "Security Kit" to enhance security measures within the application.

- **Network Security Enhancements**:
  - Employ a firewall to restrict incoming and outgoing traffic to only necessary ports and services. This includes managing proper rules for services like RPC and ensuring that only required RPC services are exposed.
  - Use network segmentation to isolate the web server and database server in separate network zones to reduce the scope of potential breaches.

- **Database Security**:
  - Ensure that database access is secured and uses encrypted connections to prevent eavesdropping on sensitive transactions. Use complex, strong passwords for database accounts and restrict database access to specific IP addresses.

- **Regular Security Audits and Penetration Testing**:
  - Conduct regular security audits and penetration tests to identify and mitigate new vulnerabilities. This should include both automated scans and manual testing to cover a wide range of potential security issues.

- **User Education and Awareness**:
  - Provide ongoing security training for all users, especially those with administrative access, to recognize phishing attempts, avoid common security pitfalls, and use strong, unique passwords managed through a password manager.

By implementing these recommendations, the system's overall security posture can be significantly enhanced to protect against known threats and vulnerabilities, as well as to prepare for new security challenges in the future.

### Tool References

This appendix provides details and references for the tools used during the penetration test. These tools were instrumental in discovering vulnerabilities and exploiting them.

- **Metasploit**: A powerful tool for developing and executing exploit code against a remote target machine. More information can be found at [Metasploit's official website](https://www.metasploit.com/).
- **Nmap**: A network scanning tool used to discover devices and services on a network, and for auditing network security. Learn more about Nmap at [Nmap's official site](https://nmap.org/).
- **DIRB**: A Web Content Scanner used for discovering non-linked content (hidden directories and files) in web applications. More details are available on the [official DIRB webpage](http://dirb.sourceforge.net/).
- **Python**: Used to enhance the shell obtained during the exploitation phase. Information on Python can be found at [Python's homepage](https://python.org).

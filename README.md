# JaySenScan

A Burp Suite plugin built on the 2025.8 Montoya API, integrating high-risk vulnerability detection with request/response encryption & decryption — designed to boost efficiency and flexibility in web security penetration testing.

[![Downloads](https://img.shields.io/github/downloads/jaysen13/jaysenscan/total.svg)](https://github.com/jaysen13/jaysenscan/releases)


## Motivation

Do these pain points sound familiar during your pentests?

- Target HTTP traffic is encrypted — signature verification, parameter encryption, and other complex scenarios
- You want to edit encrypted packets in plaintext within Repeater / Intruder
- You need precise control over which domains to scan, avoiding unintended targets
- In encrypted environments, scan payloads must be automatically encrypted before they take effect
- Tools like sqlmap and xray can't directly scan encrypted targets
- Too many plugins make Burp sluggish — you need a lightweight solution
- You need to retain scan logs for later review and analysis

JaySenScan was built to solve all of the above — combining traffic encryption/decryption with vulnerability scanning in a single plugin, streamlining pentesting workflows in encrypted environments.


## Core Features

### 🔑 Automatic Encryption / Decryption

- Full module support: covers all Burp modules (Proxy, Repeater, Intruder, etc.)
- Customizable interface: flexible encryption/decryption logic via HTTP API
- Seamless experience: edit in plaintext, transmit encrypted — no manual conversion

### 🔍 High-Risk Vulnerability Scanning

- Built-in detection: Fastjson deserialization, Log4j deserialization, Spring endpoint unauthorized access, Shiro deserialization (550/721), Shiro authorization bypass
- Smart adaptation: payloads are automatically encrypted before sending in encrypted environments
- Deduplication: avoids scanning the same target repeatedly within 5 minutes

### 🔗 Security Tool Integration

- Mainstream tool compatibility: seamless integration with sqlmap, xray, and more
- Encryption barrier removed: payloads sent by external tools are automatically encrypted by the plugin


## Demo

### Auto Encryption / Decryption

![Auto Encryption/Decryption](./README.assets/自动加解密.gif)

### Integration with sqlmap

![sqlmap Integration](./README.assets/联动sqlmap.gif)


## Getting Started (First-Time Users Must Read)

### Encryption / Decryption

#### How It Works

Packet flow within Burp:

1. Client → Burp (encrypted request)
2. Burp → Server (encrypted request)
3. Server → Burp (encrypted response)
4. Burp → Client (encrypted response)

![Packet Flow](./README.assets/image-20251129155440108-1764415249254-135.png)

The plugin hooks these 4 points to achieve automatic encryption/decryption:

- **RequestReceived**: handles the encrypted request from client to Burp (decrypt)
- **RequestToBeSent**: handles the plaintext request from Burp to server (encrypt)
- **ResponseReceived**: handles the encrypted response from server to Burp (decrypt)
- **ResponseToBeSent**: handles the plaintext response from Burp to client (encrypt)


#### Configuration Steps

##### Basic Plugin Configuration

- Check "Enable Encryption/Decryption"
- Enter the encryption/decryption API endpoint (e.g. `http://127.0.0.1:5000`)
- Configure the target domain (second-level domain, e.g. `baidu.com`; `*` or empty means all domains)
- Click "Save Configuration" to apply

![Basic Configuration](./README.assets/image-20260521083516403.png)


##### ⚠️ Required: Add JVM Parameter to Burp Startup Command

Shiro550 URLDNS chain construction requires adding a parameter to the Burp startup command.

Using a `.bat` file as an example:

![Bat File](./README.assets/image-20260520173532529.png)

Add the following parameter **before** `-jar` (note: a space before and after):

```
--add-opens java.base/java.net=ALL-UNNAMED
```

![Add Parameter](./README.assets/image-20260520173633267.png)

Once added, Shiro550 / weak-key exploitation will work correctly.

##### Implementing the Encryption/Decryption API

You need to implement an HTTP service for encryption/decryption logic. Two reference files are provided:

- `__jaysendata.py` (data structure definitions, no modification needed)

```python
from dataclasses import dataclass
from typing import Dict

# Request data structure
@dataclass
class JaysenReqData:
    method: str                  # Request method (GET/POST, etc.)
    paramters: Dict[str, str]    # Request parameters
    headers: Dict[str, str]      # Request headers
    body: str                    # Request body

# Response data structure
@dataclass
class JaysenRespData:
    headers: Dict[str, str]      # Response headers
    body: str                    # Response body
```

- `jaysenscan.py` (HTTP service template — fill in your encryption/decryption logic in the designated areas)

```python
from flask import Flask, request, jsonify
from __jaysendata import JaysenReqData, JaysenRespData
app = Flask(__name__)

# Client → Burp: decrypt request
@app.route('/RequestReceived', methods=['POST'])
def request_received():
    jaysendata = JaysenReqData(**request.get_json())
    # ==================== Write decryption logic here ====================
    # Example: jaysendata.body = aes_decrypt(jaysendata.body)
    # ====================================================================
    return jsonify(jaysendata)

# Burp → Server: encrypt request
@app.route('/RequestToBeSent', methods=['POST'])
def handle_request():
    jaysendata = JaysenReqData(**request.get_json())
    # ==================== Write encryption logic here ====================
    # Example: jaysendata.body = aes_encrypt(jaysendata.body)
    # ====================================================================
    return jsonify(jaysendata)

# Server → Burp: decrypt response
@app.route('/ResponseReceived', methods=['POST'])
def ResponseReceived():
    jaysendata = JaysenRespData(**request.get_json())
    # ==================== Write decryption logic here ====================
    # ====================================================================
    return jsonify(jaysendata)

# Burp → Client: encrypt response
@app.route('/ResponseToBeSent', methods=['POST'])
def ResponseToBeSent():
    jaysendata = JaysenRespData(**request.get_json())
    # ==================== Write encryption logic here ====================
    # ====================================================================
    return jsonify(jaysendata)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
```

> Tip: You only need to write logic inside the `#===============` blocks. Any programming language works, as long as these four endpoints are implemented.


### Vulnerability Scanning

#### Basic Configuration

1. Configure DNSLog service (supports Burp Collaborator or CEYE)
   - Burp Professional can use Collaborator (click "Auto-Generate Domain")
   - Burp Community Edition requires CEYE with API credentials
2. Select the vulnerability scan types to enable (Fastjson / Log4j / Spring / Shiro)
3. Click "Save Configuration"

![Scan Configuration](./README.assets/image-20260520161533825.png)
<img src="./README.assets/image-20260520161625096.png" alt="DNSLog Config" style="zoom: 67%;" />

The Spring directory scan configuration panel contains two fields: **File Extension Filter** and **Keyword Filter**.

> ⚠️ Both the encryption/decryption feature and the vulnerability scanner will skip traffic matching the specified file extensions or keywords.


#### Spring Endpoint Scanning

1. Configure scan trigger conditions: scanning kicks in when the request path contains specified keywords
2. Scan path file: default path is `C:\Users\$USER\.burp\springapiscan.txt` (pre-populated with common paths)
3. Recursive scanning: e.g. `/api/a/b/c` triggers scans on `/api/a/b/c`, `/api/a/b`, `/api/a`, `/api`, `/`
4. Deduplication: avoids scanning the same path within 5 minutes

![Spring Scan](./README.assets/image-20260520161734228.png)
![Path File Example](./README.assets/image-20251129161538373-1764415249254-141.png)


## Real-World Examples

A dedicated testbed is available: [jaysenscandemo](https://github.com/Jaysen13/jaysenscandemo) — includes 5 typical vulnerability scenarios to quickly master the plugin.

![Testbed Scenarios](./README.assets/image-20251129163117132-1764415249254-137.png)


### 1. Fastjson Detection with AES Encryption

1. Start the testbed's `Aes_FastJson.py` encryption/decryption service
2. Configure the plugin API endpoint to `http://127.0.0.1:5000`
3. Send a test request — Burp automatically decrypts and displays it in plaintext
4. The plugin generates an encrypted detection payload and verifies the vulnerability via DNSLog

![Fastjson Detection](./README.assets/image-20260520162637951.png)

The plugin replaces the JSON data with the payload, encrypts it according to your specified logic, and sends it. Once the DNS request is captured, the result appears in the scan panel.

![Fastjson Result](./README.assets/image-20260520170034623.png)


### 2. Log4j Detection with AES Encryption

1. Start the `Aes_Log4j.py` encryption/decryption service
2. Send a request containing trigger characters — the plugin automatically decrypts it
3. The plugin generates an encrypted Log4j payload for detection
4. Vulnerability is confirmed via DNSLog callback monitoring

![Log4j Detection](./README.assets/image-20260520165956203.png)

As shown: the Log4j payload is automatically injected into POST parameters, encrypted, and transmitted. The DNS callback confirms the vulnerability in the results panel.

![Log4j Result](./README.assets/image-20260520171134629.png)


### 3. SQL Injection Detection with sqlmap Integration

1. Start the `Aes_Sql.py` encryption/decryption service

2. Capture a login request and obtain the decrypted plaintext data

3. Save the plaintext request as `data.txt` and launch sqlmap through the Burp proxy:

   ```shell
   python sqlmap.py -r data.txt --proxy=http://127.0.0.1:8080
   ```

4. sqlmap's payloads are automatically encrypted by the plugin, successfully detecting injection points

![SQL Injection Integration](./README.assets/image-20251129170217229-1764415249254-145.png)


### 4. Shiro Deserialization & Authorization Bypass

#### Shiro550 Detection

1. Ensure DNSLog is configured (Collaborator or CEYE)
2. When the plugin identifies a target as a Shiro framework, it automatically iterates through the built-in shiro_keys dictionary (stored at `~/.burp/shirokeys.txt`)
3. Encrypted URLDNS payloads are constructed and sent — a DNSLog callback confirms the vulnerability

#### Shiro721 Detection

1. Prerequisite: the target request must already contain a valid `rememberMe` cookie (user is logged in)
2. The plugin tampers with the last bytes of the ciphertext, checking for `Set-Cookie: rememberMe=deleteMe` to confirm the Padding Oracle
3. Without the encryption key, the Padding Oracle channel can be leveraged to decrypt/re-encrypt, ultimately achieving deserialization RCE

#### Shiro Authorization Bypass

1. The plugin automatically constructs bypass payloads (e.g. `/..;/`, `/;/`, `/%20/`, etc.)
2. Compares response differences against the original request to identify authorization bypass vulnerabilities

> Found Shiro550 keys are annotated in the `JaySen-shiroKey` request header for follow-up exploitation with other tools.

![Shiro Detection](./README.assets/image-20260520161340223.png)


### 5. Spring Endpoint Unauthorized Access Detection

1. Configure file extension and keyword filters in the "Spring Directory Scan Config" panel to avoid scanning static resources
2. The plugin loads common Spring endpoint paths from `~/.burp/springapiscan.txt` (e.g. `/actuator`, `/swagger-ui.html`, `/druid/`, `/doc.html`, etc.)
3. Recursive scanning: starting from the current path, payloads are appended layer by layer, e.g. `/api/user/list` triggers `/api/user/list/actuator` → `/api/user/actuator` → `/api/actuator` → `/actuator`
4. Hits are automatically tagged as "Spring Unauthorized Access"

![Spring Scan](./README.assets/image-20260520161734228.png)
![Path File Example](./README.assets/image-20251129161538373-1764415249254-141.png)


## Tips & Tricks

- Enable Burp's "Show edited data" option to view decrypted content directly (see screenshot)
  ![Burp Display Setting](./README.assets/image-20251129163738709-1764415249254-146.png)
- The encryption/decryption API supports any language — Java, Go, Node.js, etc. — just keep the JSON structure consistent
- Scan records are automatically retained and can be reviewed in the plugin's history panel


## FAQ

- **Q: Does the encryption/decryption API have to be Python?**  
  A: No. Any language works as long as the same HTTP interface is implemented.

- **Q: Can I use Burp Community Edition?**  
  A: Yes, but Collaborator is not supported. Configure CEYE as the DNSLog service instead.

- **Q: What if the encryption/decryption API returns an error?**  
  A: Verify the API endpoint is correct and the service is running. Check the Burp Output log for specific error details.

- **Q: Why isn't Shiro550 scanning producing any results?**  
  A: Confirm three things: ① DNSLog is configured; ② `--add-opens java.base/java.net=ALL-UNNAMED` is added to the Burp startup command; ③ `~/.burp/shirokeys.txt` exists and is not empty.

- **Q: Why isn't Shiro721 scanning triggering?**  
  A: Shiro721 detection requires a valid `rememberMe` cookie in the request (i.e. the user is logged in). It skips automatically if no cookie is present.

- **Q: Will more vulnerability detection modules be added?**  
  A: Yes — the plugin is under active development. Feel free to leave suggestions!


## Acknowledgments

- [Galaxy](https://github.com/outlaws-bai/Galaxy) — The encryption/decryption traffic hooking and automatic encryption/decryption implementation in this project was inspired by Galaxy's hook mechanism. Thanks to [outlaws-bai](https://github.com/outlaws-bai) for open-sourcing it.


## Author & Feedback

### 👨‍💻 Author

- Author: JaySen
- Email: 3147330392@qq.com
- GitHub: [Jaysen13/JaySenScan](https://github.com/Jaysen13/JaySenScan)

### 📬 Feedback & Contributions

- If you encounter bugs or have feature suggestions, feel free to submit a GitHub Issue
- The plugin is under continuous iteration — more vulnerability types will be supported in the future

### 📄 License

This project is open-sourced under the CC BY-NC-SA 4.0 license: non-commercial use, modification, and redistribution are allowed (with attribution), **commercial sales of any kind are strictly prohibited** (including derivative works).


⭐ Star History

If this project helps you, a Star would be greatly appreciated! Your support keeps me motivated.

<img src="./README.assets/image-20260520171657363.png" alt="Star" style="zoom:50%;" />

<a href="https://www.star-history.com/?repos=Jaysen13%2Fjaysenscan&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=Jaysen13/jaysenscan&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=Jaysen13/jaysenscan&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=Jaysen13/jaysenscan&type=date&legend=top-left" />
 </picture>
</a>

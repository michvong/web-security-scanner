# web-security-scanner

A security detector which identifies vulnerabilties and risks in the OWASP Juice Shop.

## **Getting Started**

- To run OWASP Juice Shop, follow the instructions here: `https://github.com/juice-shop/juice-shop`

### **Installation**

1. Create an `.env` file under the root directory with the following:

```
HOST=http://localhost:3000
HTTP_PROXY=http://127.0.0.1:8080
HTTPS_PROXY=http://127.0.0.1:8080
LOG_FILE=<log data from OWASP Juice Shop>
ADMIN_EMAIL=admin@juice-sh.op
ADMIN_PASSWORD=admin123
USER_EMAIL=test_email@example.com
USER_PASSWORD=testing
```

2. Under `data/urls.txt`, enter a list of URLs to test out.

3. Install the required dependencies using `pip install -r requirements.txt`

4. Run the program using `python3 -m main` in the root directory.
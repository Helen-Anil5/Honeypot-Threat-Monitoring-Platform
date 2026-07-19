import logging
import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

# Configure logging to save data to a file and print to the console
LOG_FILE = 'honeypot_logs.txt'
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class HoneypotHandler(BaseHTTPRequestHandler):
    
    # Suppress default stderr logging from the base class
    def log_message(self, format, *args):
        pass

    def log_event(self, message):
        """Helper function to log to both file and console"""
        logging.info(message)
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {message}")

    def do_GET(self):
        """Handle incoming GET requests (e.g., viewing the login page)"""
        client_ip = self.client_address[0]
        user_agent = self.headers.get('User-Agent', 'Unknown')
        
        # 🛑 NEW: Handle favicon requests gracefully to eliminate log noise
        if self.path == '/favicon.ico':
            self.log_event(f"GET Request from {client_ip} | Path: {self.path} | UA: {user_agent} [Auto-Browser Request]")
            self.send_response(204)  # 204 No Content tells the browser to stop asking
            self.end_headers()
            return

        self.log_event(f"GET Request from {client_ip} | Path: {self.path} | UA: {user_agent}")

        # Send HTTP 200 OK response
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        # Serve a fake, enticing admin login page
        html_response = """
        <html>
        <head><title>Router Admin Panel</title></head>
        <body style="font-family: Arial; text-align: center; margin-top: 50px;">
            <h1>NetGear Pro Router - Admin Login</h1>
            <form action="/login" method="POST">
                <p>Username: <input type="text" name="username"></p>
                <p>Password: <input type="password" name="password"></p>
                <p><input type="submit" value="Login"></p>
            </form>
        </body>
        </html>
        """
        self.wfile.write(html_response.encode('utf-8'))

    def do_POST(self):
        """Handle incoming POST requests (e.g., submitted credentials)"""
        client_ip = self.client_address[0]
        
        # Safely read the POST data
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 0:
            post_data = self.rfile.read(content_length).decode('utf-8', errors='ignore')
        else:
            post_data = "No data received"

        self.log_event(f"POST Request from {client_ip} | Path: {self.path} | Payload: {post_data}")

        # Send a fake "Invalid Credentials" response to encourage retrying
        self.send_response(401)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        error_html = "<html><body><h1>401 Unauthorized: Invalid Username or Password</h1></body></html>"
        self.wfile.write(error_html.encode('utf-8'))

    def do_HEAD(self):
        """Handle HEAD requests often used by automated scanners"""
        client_ip = self.client_address[0]
        self.log_event(f"HEAD Request from {client_ip} | Path: {self.path}")
        self.send_response(200)
        self.end_headers()

def run_honeypot(port=8080):
    server_address = ('', port)
    httpd = HTTPServer(server_address, HoneypotHandler)
    
    print(f"=========================================")
    print(f" Honeypot Active on Port {port}")
    print(f" Local URL: http://localhost:{port}")
    print(f" Logs saving to: {LOG_FILE}")
    print(f" Press CTRL+C to stop.")
    print(f"=========================================")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down honeypot...")
        httpd.server_close()

if __name__ == '__main__':
    # You can change the port here. 
    # Note: Ports below 1024 require Administrator/root privileges.
    run_honeypot(port=8080)
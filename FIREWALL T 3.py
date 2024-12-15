from http.server import BaseHTTPRequestHandler, HTTPServer

class FirewallHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Get the headers and content length
        content_type = self.headers.get('Content-Type')
        user_agent = self.headers.get('User-Agent')
        content_length = int(self.headers.get('Content-Length'))
        post_data = self.rfile.read(content_length).decode('utf-8')

        # Define malicious patterns to filter
        malicious_patterns = ["class.module.classLoader", "module.classLoader"]
        suspicious_content_types = ["application/x-www-form-urlencoded"]
        suspicious_user_agents = [None, '', 'curl/7.x.x']

        # Check for malicious query parameters
        if any(pattern in post_data for pattern in malicious_patterns):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Blocked: Malicious parameter detected.")
            return

        # Check for suspicious Content-Type header
        if content_type in suspicious_content_types and any(pattern in post_data for pattern in malicious_patterns):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Blocked: Malicious Content-Type detected.")
            return

        # Check for suspicious User-Agent header
        if user_agent in suspicious_user_agents:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Blocked: Suspicious User-Agent detected.")
            return

        # Allow legitimate requests
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Request processed successfully.")

if __name__ == "__main__":
    # Set up and run the server
    server_address = ('', 8080)  # Listen on all interfaces, port 8080
    httpd = HTTPServer(server_address, FirewallHTTPRequestHandler)
    print("Firewall HTTP server is running on port 8080...")
    httpd.serve_forever()

from mitmproxy import http, ctx
import uuid

pending_requests = {}

class CancelWaitRedirectAddon:

    def load(self, loader):
        print("[STARTUP] Proxy has started.")


    def request(self, flow: http.HTTPFlow):
        if flow.request.method.upper() == "POST" and "fakehost.mitm" not in flow.request.host:
            request_id = str(uuid.uuid4())
            ref = flow.request.headers.get("Referer", "")

            pending_requests[request_id] = {
                "status": "pending",
                "ref": ref
            }
            print(f"[REQUEST] Generated req_id={request_id}")

            # Tell the client to redirect to /waiting_page?req_id=XYZ
            flow.response = http.Response.make(
                303,
                b"",
                {
                    "Location": f"http://fakehost.mitm/waiting_page?req_id={request_id}"
                }
            )

    def requestheaders(self, flow: http.HTTPFlow):
        if "fakehost.mitm" in flow.request.host:
            path = flow.request.path
            print(f"Got request to fakehost.mitm: {flow.request.method} {path}")
            if path.startswith("/waiting_page"):
                self.serve_waiting_page(flow)
            elif path.startswith("/check_approval"):
                self.handle_check_approval(flow)
            elif path.startswith("/approve"):
                self.handle_approve(flow)
            elif path.startswith("/reject"):
                self.handle_reject(flow)
            else:
                flow.response = http.Response.make(404, b"Not Found")

    def serve_waiting_page(self, flow: http.HTTPFlow):
        # Log to see what method & query we got
        print(f"serve_waiting_page: method={flow.request.method}, query={flow.request.query}")

        req_id = flow.request.query.get("req_id", [""])

        print(f"[WAITING_PAGE] Received req_id={req_id}")
        print(f"[WAITING_PAGE] pending_requests keys={list(pending_requests.keys())}")

        if not req_id:
            flow.response = http.Response.make(
                404, b"Missing req_id param", {"Content-Type": "text/plain"}
            )
            return

        if req_id not in pending_requests:
            flow.response = http.Response.make(
                404, b"Invalid req_id", {"Content-Type": "text/plain"}
            )
            return

        ref = pending_requests[req_id].get("ref", "")

        waiting_html = f"""
        <html>
        <head><title>Request Pending Approval</title></head>
        <body>
            <h1>This request is pending approval...</h1>
            <p>Request ID: {req_id}</p>
            <script>
            const reqId = "{req_id}";
            // Poll every 2 seconds
            setInterval(async () => {{
                let resp = await fetch("http://fakehost.mitm/check_approval?req_id=" + reqId);
                let data = await resp.json();
                if (data.status === "approved") {{
                    if ("{ref}" && "{ref}".length > 0) {{
                        window.location = "{ref}";
                    }} else {{
                        window.history.back();
                    }}
                }} else if (data.status === "rejected") {{
                    document.body.innerHTML = "<h1>Request was rejected.</h1>";
                }}
            }}, 2000);
            </script>
        </body>
        </html>
        """

        html_bytes = waiting_html.encode("utf-8")
        headers = {
            "Content-Type": "text/html",
            "Content-Length": str(len(html_bytes))
        }

        # Serve the waiting page even if it's a POST
        flow.response = http.Response.make(
            200,
            html_bytes,
            headers
        )

    def handle_check_approval(self, flow: http.HTTPFlow):
        req_id = flow.request.query.get("req_id", [""])
        entry = pending_requests.get(req_id)
        if not entry:
            flow.response = http.Response.make(404, b"Invalid request_id")
            return

        resp_data = {"status": entry["status"]}
        flow.response = http.Response.make(
            200,
            bytes(str(resp_data), "utf-8"),
            {"Content-Type": "application/json"}
        )

    def handle_approve(self, flow: http.HTTPFlow):
        req_id = flow.request.query.get("req_id", [""])
        if req_id in pending_requests:
            pending_requests[req_id]["status"] = "approved"
            flow.response = http.Response.make(
                200, b"Request approved.", {"Content-Type": "text/plain"}
            )
        else:
            flow.response = http.Response.make(404, b"Invalid request_id")

    def handle_reject(self, flow: http.HTTPFlow):
        req_id = flow.request.query.get("req_id", [""])
        if req_id in pending_requests:
            pending_requests[req_id]["status"] = "rejected"
            flow.response = http.Response.make(
                200, b"Request rejected.", {"Content-Type": "text/plain"}
            )
        else:
            flow.response = http.Response.make(404, b"Invalid request_id")

addons = [CancelWaitRedirectAddon()]

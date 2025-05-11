import base64
import json
from urllib.parse import urljoin, urlparse

import requests

from mitmproxy import http, ctx
import uuid

pending_requests = {}

HOP_BY_HOP = {
    "connection","keep-alive","proxy-authorization",
    "proxy-authenticate","te","trailer",
    "transfer-encoding","upgrade"
}

class CancelWaitRedirectAddon:

    def load(self, loader):
        print("[STARTUP] Proxy has started.")


    def request(self, flow: http.HTTPFlow):
        if flow.request.method.upper() == "POST" and "fakehost.mitm" not in flow.request.host:
            request_id = str(uuid.uuid4())
            ref = flow.request.headers.get("Referer", "")

            clean_headers = {
                k: v for k, v in flow.request.headers.items()
                if k.lower() not in HOP_BY_HOP
            }
            pending_requests[request_id] = {
                "status": "pending",
                "ref": ref,
                "req": {
                    "method": flow.request.method,
                    "url": flow.request.url,
                    "headers": dict(clean_headers),
                    "body": base64.b64encode(flow.request.get_content()).decode("ascii")

                }
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
            elif path.startswith("/replay_request"):
                self.handle_replay_request(flow)
            else:
                print(f"[REQUEST_HEADERS] no handler for {path!r}, sending 404")
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
                    window.location.href = `/replay_request?req_id={req_id}`;
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
        body = json.dumps(resp_data).encode("utf-8")
        flow.response = http.Response.make(
            200,
            body,
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

    def handle_replay_request(self, flow: http.HTTPFlow):
        try:
            rid = flow.request.query.get("req_id", "")  # plain string
            entry = pending_requests.pop(rid, None)
            if not entry or entry["status"] != "approved":
                flow.response = http.Response.make(
                    400, b"Not approved", {b"Content-Type": b"text/plain"}
                )
                return

            orig = entry["req"]
            real_host = urlparse(orig["url"]).hostname

            resp = requests.request(
                method=orig["method"],
                url=orig["url"],
                headers={k: v for k, v in orig["headers"].items()
                         if k.lower() not in HOP_BY_HOP},
                data=base64.b64decode(orig["body"]),
                allow_redirects=False
            )

            # Build headers to send back
            response_headers = []

            # 1) Copy non-hop-by-hop, non-Set-Cookie headers
            for k, v in resp.headers.items():
                lk = k.lower()
                if lk in HOP_BY_HOP or lk == "set-cookie":
                    continue
                if lk == "location":
                    v = urljoin(orig["url"], v)
                response_headers.append((k.encode(), v.encode()))

            # 2) Rewrite & forward all Set-Cookie headers
            raw = getattr(resp.raw, "_original_response", None)
            raw_cookies = raw.msg.get_all("Set-Cookie") if raw else []
            for cookie in raw_cookies or []:
                parts = [p.strip() for p in cookie.split(";")]
                new_parts = []
                for p in parts:
                    lp = p.lower()
                    if lp.startswith("domain="):
                        # force domain to the real host
                        new_parts.append(f"Domain={real_host}")
                    elif lp == "secure":
                        # drop Secure so it can be set over HTTP proxy
                        continue
                    else:
                        new_parts.append(p)
                new_cookie = "; ".join(new_parts)
                response_headers.append((b"Set-Cookie", new_cookie.encode()))

            # 3) Body: empty for redirects, else actual content
            body = b"" if 300 <= resp.status_code < 400 else resp.content

            flow.response = http.Response.make(
                resp.status_code,
                body,
                response_headers
            )

        except Exception as e:
            ctx.log.error(f"[REPLAY_REQ ERROR] {e!r}")
            flow.response = http.Response.make(
                502,
                f"Proxy replay error: {e}".encode(),
                {b"Content-Type": b"text/plain"}
            )

addons = [CancelWaitRedirectAddon()]

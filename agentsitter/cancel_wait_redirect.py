import base64
import json
import threading
import traceback

import requests
import sseclient

from mitmproxy import http, ctx
import uuid

pending_requests = {}

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authorization",
    "proxy-authenticate", "te", "trailer",
    "transfer-encoding", "upgrade"
}

class CancelWaitRedirectAddon:
    def __init__(self, notify_url, token):
        self.notify_url = notify_url
        self.token = token

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

            # Redirect to waiting page with new path prefix
            wait_url = f"{flow.request.scheme}://{flow.request.host}/__auth_proxy_waiting?req_id={request_id}"
            flow.response = http.Response.make(
                303,
                b"",
                {"Location": wait_url}
            )

            def wait_for_approval(req_id):
                details = pending_requests[req_id]
                # pass req_id as a query so the server only sends events for it
                requests.post(
                    f"{self.notify_url}/api/request-approval",
                    headers={"Authorization": f"Bearer {self.token}"},
                    json={
                        "req_id": req_id,
                        "details": details
                    }
                )
                url = f"{self.notify_url}/api/stream?req_id={req_id}"
                headers = {
                    "Authorization": f"Bearer {self.token}",
                    "Accept": "text/event-stream"
                }
                stream = requests.get(f"{url}", headers=headers, stream=True)
                client = sseclient.SSEClient(stream)
                try:
                    for ev in client.events():
                        data = json.loads(ev.data)
                        if data["req_id"] == req_id and data["status"] in ("approved","rejected"):
                            pending_requests[req_id]["status"] = data["status"]
                            print(f"[APPROVAL] {data['status']} req_id={req_id}")
                            break
                except Exception as e:
                    print(f"[ERROR] Error in wait_for_approval: {e}")
                    traceback.print_exc()
                finally:
                    client.close()

            threading.Thread(
                target=wait_for_approval,
                args=(request_id,),
                daemon=True
            ).start()

    def requestheaders(self, flow: http.HTTPFlow):
        host = flow.request.host
        path = flow.request.path

        if "fakehost.mitm" in host:
            print(f"[FAKEHOST] {flow.request.method} {path}")
            if path.startswith("/approve"):
                self.handle_approve(flow)
            elif path.startswith("/reject"):
                self.handle_reject(flow)
            else:
                print(f"[REQUEST_HEADERS] no handler for {path!r}, sending 404")
                flow.response = http.Response.make(404, b"Not Found")
        else:
            print(f"[REALHOST] {flow.request.method} {path}")
            if path.startswith("/__auth_proxy_waiting"):
                self.serve_waiting_page(flow)
            elif path.startswith("/__auth_proxy_check"):
                self.handle_check_approval(flow)
            elif path.startswith("/__auth_proxy_replay"):
                self.handle_replay_request(flow)

    def serve_waiting_page(self, flow: http.HTTPFlow):
        req_id = flow.request.query.get("req_id")
        if not req_id:
            flow.response = http.Response.make(
                404, b"Missing req_id param", {"Content-Type": "text/plain"}
            )
            return

        req_id = req_id[0] if isinstance(req_id, list) else req_id
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
            setInterval(async () => {{
                let resp = await fetch("/__auth_proxy_check?req_id=" + reqId);
                let data = await resp.json();
                if (data.status === "approved") {{
                    window.location.href = "/__auth_proxy_replay?req_id=" + reqId;
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

        flow.response = http.Response.make(
            200,
            html_bytes,
            headers
        )

    def handle_check_approval(self, flow: http.HTTPFlow):
        req_id = flow.request.query.get("req_id")
        req_id = req_id[0] if isinstance(req_id, list) else req_id
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
        req_id = flow.request.query.get("req_id")
        req_id = req_id[0] if isinstance(req_id, list) else req_id
        if req_id in pending_requests:
            pending_requests[req_id]["status"] = "approved"
            flow.response = http.Response.make(
                200, b"Request approved.", {"Content-Type": "text/plain"}
            )
        else:
            flow.response = http.Response.make(404, b"Invalid request_id")

    def handle_reject(self, flow: http.HTTPFlow):
        req_id = flow.request.query.get("req_id")
        req_id = req_id[0] if isinstance(req_id, list) else req_id
        if req_id in pending_requests:
            pending_requests[req_id]["status"] = "rejected"
            flow.response = http.Response.make(
                200, b"Request rejected.", {"Content-Type": "text/plain"}
            )
        else:
            flow.response = http.Response.make(404, b"Invalid request_id")

    def handle_replay_request(self, flow: http.HTTPFlow):
        try:
            req_id = flow.request.query.get("req_id")
            req_id = req_id[0] if isinstance(req_id, list) else req_id

            entry = pending_requests.pop(req_id, None)
            if not entry or entry["status"] != "approved":
                flow.response = http.Response.make(
                    400, b"Not approved", {"Content-Type": "text/plain"}
                )
                return

            orig = entry["req"]
            resp = requests.request(
                method=orig["method"],
                url=orig["url"],
                headers={k: v for k, v in orig["headers"].items()
                         if k.lower() not in HOP_BY_HOP},
                data=base64.b64decode(orig["body"]),
                allow_redirects=False
            )

            response_headers = []
            for k, v in resp.headers.items():
                if k.lower() not in HOP_BY_HOP:
                    response_headers.append((k.encode(), v.encode()))

            raw = getattr(resp.raw, "_original_response", None)
            raw_cookies = raw.msg.get_all("Set-Cookie") if raw else []
            for cookie in raw_cookies or []:
                response_headers.append((b"Set-Cookie", cookie.encode()))

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
                {"Content-Type": "text/plain"}
            )
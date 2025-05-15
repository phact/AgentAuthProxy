# server.py
import json
import asyncio
import traceback
import httpx
import requests

from authlib.integrations.starlette_client import OAuth
from fasthtml.common import *
from monsterui.all import *
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

load_dotenv()

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")

transport = httpx.AsyncHTTPTransport(local_address="0.0.0.0")  # IPv4 only

app, rt = fast_app(
    hdrs=(
        Theme.slate.headers(),
        Title("AgentSitter.ai Approval Dashboard"),
        Meta(charset="utf-8"),
        Meta(name="viewport", content="width=device-width, initial-scale=1"),
        Link(rel="manifest", href="/static/manifest.json"),
        Script(src="https://unpkg.com/htmx.org@1.9.2"),
        Script(src="/static/sw.js", type="text/javascript"),
    )
)
app.add_middleware(SessionMiddleware, secret_key="stick-this-in-an-env-var")
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

oauth = OAuth()
oauth.register(
    name='github',
    client_id=GITHUB_CLIENT_ID,
    client_secret=GITHUB_CLIENT_SECRET,
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={
        "scope": "read:user",
        "transport": transport,
    },
)

pending = {}         # session_id -> {req_id -> asyncio.Queue}
metadata = {}        # session_id -> {req_id -> request metadata dict}



@rt('/login')
async def login(request):
    redirect_uri = str(request.url_for("auth"))
    print("Redirect I will send to GitHub:", redirect_uri)
    github = oauth.create_client('github')
    return await github.authorize_redirect(request, redirect_uri)

@rt("/logout")
async def logout(request):
    if request.session.get('user'):
        request.session.clear()          # removes 'user', 'token', etc.
        resp = RedirectResponse(url="/")
        resp.delete_cookie("session")    # the cookie name you configured
    return RedirectResponse(url="/")

@rt('/auth')
async def auth(request):
    # Exchange the authorization code for an access token
    github = oauth.create_client('github')
    token = await github.authorize_access_token(request)
    # Fetch the authenticated user’s profile from GitHub
    resp = await oauth.github.get('user', token=token)
    resp.raise_for_status()
    user = resp.json()
    # Store user info in session (or handle as you wish)
    request.session['user'] = user
    # Redirect back to your app (or render a page)
    return RedirectResponse(url="/")


@rt('/api/request-approval', methods=['POST'])
async def request_approval(request):
    data = await request.json()
    req_id = data['req_id']

    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return JSONResponse(
            {"detail": "Missing authorization header"},
            status_code=401,
        )

    try:
        scheme, token = auth_header.split(" ", 1)
    except ValueError:
        return JSONResponse(
            {"detail": "Invalid authorization header format"},
            status_code=401,
        )

    if scheme.lower() != "bearer":
        return JSONResponse(
            {"detail": "Unsupported authorization scheme"},
            status_code=401,
        )


    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
    }
    response = requests.get("https://api.github.com/user", headers=headers)
    response.raise_for_status()
    user = response.json()

    session_id = str(user.get('id'))
    
    # Initialize session dictionaries if needed
    if session_id not in pending:
        pending[session_id] = {}
    if session_id not in metadata:
        metadata[session_id] = {}
    
    q = asyncio.Queue()
    print(f"Creating queue for user_id={session_id}, req_id={req_id}: {q}")
    pending[session_id][req_id] = q
    metadata[session_id][req_id] = data
    return JSONResponse({'status': 'pending'})

@rt('/api/approve', methods=['POST'])
async def approve_request(request):
    try:
        # Try to get data from form
        form_data = await request.form()
        req_id = form_data.get('req_id')
        
        # If not in form, try JSON
        if not req_id:
            json_data = await request.json()
            req_id = json_data.get('req_id')
        
        # Get user ID from session
        user = request.session.get('user')
        if not user:
            return JSONResponse({'status': 'error', 'message': 'Not authenticated'}, status_code=401)
        
        session_id = str(user.get('id'))
        if session_id not in pending:
            return JSONResponse({'status': 'error', 'message': 'No pending requests'})
            
        print(f"Approve request received for user_id={session_id}, req_id={req_id}")
        q = pending[session_id].get(req_id)
        if q:
            print(f"Found queue for user_id={session_id}, req_id={req_id}, sending approval")
            await q.put({'req_id': req_id, 'status': 'approved'})
            del pending[session_id][req_id]
            del metadata[session_id][req_id]
        else:
            print(f"No queue found for user_id={session_id}, req_id={req_id}")
        return await get_cards_html(request)
    except Exception as e:
        print(f"Error in approve_request: {e}")
        return JSONResponse({'status': 'error', 'message': str(e)})

@rt('/api/reject', methods=['POST'])
async def reject_request(request):
    try:
        # Try to get data from form
        form_data = await request.form()
        req_id = form_data.get('req_id')
        
        # If not in form, try JSON
        if not req_id:
            json_data = await request.json()
            req_id = json_data.get('req_id')
        
        # Get user ID from session
        user = request.session.get('user')
        if not user:
            return JSONResponse({'status': 'error', 'message': 'Not authenticated'}, status_code=401)
        
        session_id = str(user.get('id'))
        if session_id not in pending:
            return JSONResponse({'status': 'error', 'message': 'No pending requests'})
            
        print(f"Reject request received for user_id={session_id}, req_id={req_id}")
        q = pending[session_id].get(req_id)
        if q:
            print(f"Found queue for user_id={session_id}, req_id={req_id}, sending rejection")
            await q.put({'req_id': req_id, 'status': 'rejected'})
            del pending[session_id][req_id]
            del metadata[session_id][req_id]
        else:
            print(f"No queue found for user_id={session_id}, req_id={req_id}")
        return await get_cards_html(request)
    except Exception as e:
        print(f"Error in reject_request: {e}")
        return JSONResponse({'status': 'error', 'message': str(e)})

@rt('/api/stream', methods=['GET'])
async def approval_stream(request):
    req_id = request.query_params.get('req_id')
    auth_header = request.headers.get('Authorization', '')
    
    # Extract token from Authorization header
    token = ''
    if auth_header.startswith('Bearer '):
        token = auth_header[7:]
    
    # Find the session_id that has this request
    session_id = None
    for sid in pending:
        if req_id in pending[sid]:
            session_id = sid
            break
    
    if not session_id or req_id not in pending[session_id]:
        return JSONResponse({'error': 'not found'}, status_code=404)
        
    q = pending[session_id][req_id]
    print(f"Stream request for req_id={req_id}, queue={q}")
    
    async def event_gen():
        print(f"Waiting for data on queue for req_id={req_id}")
        data = await q.get()
        print(f"Got data from queue: {data}")
        yield f"data: {json.dumps(data)}\n\n"
    return StreamingResponse(event_gen(), media_type='text/event-stream')  # Server-Sent Events

@rt('/api/pending')
async def list_pending(request):
    user = request.session.get('user')
    if not user:
        return JSONResponse({'status': 'error', 'message': 'Not authenticated'}, status_code=401)
    
    session_id = str(user.get('id'))
    if session_id not in metadata:
        return JSONResponse([])
    
    return JSONResponse(list(metadata[session_id].values()))

@rt('/')
async def index(request):
    user = request.session.get('user')   # None if not logged in
    if user:
        return Title("AgentSitter.ai"), Body(
            Div(
                H1("Pending Requests", cls="text-3xl font-bold mb-6 text-white"),
                await get_cards_html(request),  # Use the helper function here
                cls="max-w-4xl mx-auto p-8 bg-slate-950 min-h-screen"
            )
        )
    else:
        return Title("AgentSitter.ai"), Body(
            Div(
                Button("Login with GitHub", cls="px-4 py-2 bg-blue-600 text-white",
                       onclick="location.href='/login'"),
                id="main"
            )
        )

# Helper function to generate cards HTML
async def get_cards_html(request):
    user = request.session.get('user')
    if not user:
        return Div(id="cards", cls="space-y-6")
    
    session_id = str(user.get('id'))
    if session_id not in metadata:
        return Div(id="cards", cls="space-y-6")
    
    items = list(metadata[session_id].values())
    cards = []

    for it in items:
        req = it.get("details", {}).get("req", {})
        headers = req.get("headers", {})
        body = req.get("body", "")
        req_id = it.get("req_id")
        method = req.get("method", "UNKNOWN")
        url = req.get("url", "UNKNOWN")

        # Clean header rows
        header_list = [
            Div(
                Span(f"{k}: ", cls="font-semibold text-slate-500"),
                Span(str(v), cls="font-mono text-sm text-slate-200 break-words"),
                cls="flex flex-wrap"
            )
            for k, v in headers.items()
        ]

        card = Card(
            Div(
                H3(
                    Span(method, cls="text-indigo-400 font-semibold"),
                    " → ",
                    Span(url, cls="text-blue-300 underline"),
                    cls="text-lg"
                ),
                P("Request ID: ", A(req_id, href=f"#", cls="text-sm text-blue-400 underline")),
                P("Body: ", Span(body or "∅", cls="font-mono text-xs text-slate-300")),
                cls="mb-4 space-y-1"
            ),
            Div(
                H3("Headers", cls="text-md font-semibold text-slate-400 mb-2"),
                Div(*header_list, cls="space-y-1 bg-slate-800 border border-slate-700 rounded p-4"),
                cls="mb-4"
            ),
            Div(
                Button(
                    "Approve",
                    cls=ButtonT.primary + " px-4 py-2 text-sm",
                    **{
                        "hx-post": "/api/approve",
                        "hx-encoding": "json",
                        "hx-vals": json.dumps({"req_id": req_id}),
                        "hx-target": "#cards",
                        "hx-swap": "outerHTML"
                    }
                ),
                Button(
                    "Reject",
                    cls=ButtonT.secondary + " px-4 py-2 text-sm",
                    **{
                        "hx-post": "/api/reject",
                        "hx-encoding": "json",
                        "hx-vals": json.dumps({"req_id": req_id}),
                        "hx-target": "#cards",
                        "hx-swap": "outerHTML"
                    }
                ),
                cls="p-6 rounded-xl shadow-md border border-slate-700 bg-slate-900 text-white"
            )
        )

        cards.append(card)

    return Div(*cards, id="cards", cls="space-y-6")


#app.mount('/static', StaticFiles(directory='agentsitter/app/static'), name='static')
app.mount('/static', StaticFiles(directory='static'), name='static')

def start():
    try:
        serve(reload=False)
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    start()

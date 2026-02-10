from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    # Target the specific string from Bob's server
    if b"This is Bob's web server!" in flow.response.content:
        # Replace with the required text plus a clear indicator for the screenshot
        flow.response.content = b"<h1>This is not Bob!</h1><p>Mallory has intercepted this session. &#128521;</p>"
        print("[+] MITM SUCCESS: Bob's response has been modified!")

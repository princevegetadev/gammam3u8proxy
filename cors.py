import json
import os
from fastapi import Request, Response, Cookie
from fastapi.responses import RedirectResponse
from request_helper import Requester
from typing import Annotated
from urllib.parse import unquote, urlparse


async def cors(request: Request, origins, method="GET") -> Response:
    current_domain = request.headers.get("origin") or origins
    allow_origin_list = origins.replace(", ", ",").split(",") if origins != "*" else ["*"]

    if origins != "*" and current_domain not in allow_origin_list:
        return Response("Forbidden origin", status_code=403)

    raw_url = request.query_params.get('url')
    if not raw_url:
        return Response("Missing 'url' param", status_code=400)
    
    # Prevent nested proxy calls
    decoded_url = unquote(raw_url)
    if "gammam3u8proxy-fxsb.vercel.app" in decoded_url:
        # Extract the *real* target URL from the nested proxy call
        inner_url = urlparse(decoded_url).query
        if inner_url.startswith("url="):
            raw_url = unquote(inner_url.split("url=", 1)[-1])
    
    url = raw_url
    if not url:
        return Response("Missing 'url' param", status_code=400)

    file_type = request.query_params.get('type')
    try:
        requested = Requester(str(request.url))
        main_url = requested.host + requested.path + "?url="
        url += "?" + requested.query_string(requested.remaining_params)

        requested = Requester(url)
        hdrs = request.headers.mutablecopy()
        hdrs["Accept-Encoding"] = ""

        hdrs.update(json.loads(request.query_params.get("headers", "{}").replace("'", '"')))
        content, headers, code, cookies = requested.get(
            data=None,
            headers=hdrs,
            cookies=request.cookies,
            method=request.query_params.get("method", method),
            json_data=json.loads(request.query_params.get("json", "{}")),
            additional_params=json.loads(request.query_params.get("params", "{}"))
        )

        headers['Access-Control-Allow-Origin'] = current_domain
        headers['Access-Control-Allow-Credentials'] = 'true'

        # Strip problematic headers
        for key in ['Vary', 'Content-Encoding', 'Transfer-Encoding', 'Content-Length']:
            headers.pop(key, None)

        if (file_type == "m3u8" or ".m3u8" in url) and code != 404:
            content = content.decode("utf-8")
            new_content = ""
            for line in content.splitlines():
                if line.startswith("#"):
                    new_content += line
                elif line.startswith("/"):
                    new_content += main_url + requested.safe_sub(requested.host + line)
                elif line.startswith("http"):
                    new_content += main_url + requested.safe_sub(line)
                elif line.strip():
                    new_content += main_url + requested.safe_sub(
                        requested.host + '/' +
                        '/'.join(str(requested.path).split("?")[0].split("/")[:-1]) +
                        '/' + requested.safe_sub(line)
                    )
                new_content += "\n"
            content = new_content

        # Rewrite relative location redirects
        if "location" in headers:
            if headers["location"].startswith("/"):
                headers["location"] = requested.host + headers["location"]
            headers["location"] = main_url + headers["location"]

        resp = Response(content, code, headers=headers)
        resp.set_cookie("_last_requested", requested.host, max_age=3600, httponly=True)
        return resp

    except Exception as e:
        return Response(
            f"Proxy failed: {str(e)}",
            status_code=500,
            headers={
                "Access-Control-Allow-Origin": current_domain,
                "Access-Control-Allow-Credentials": "true",
                "Content-Type": "text/plain"
            }
        )

def add_cors(app, origins, setup_with_no_url_param=False):
    cors_path = os.getenv('cors_url', '/cors')

    @app.get(cors_path)
    async def cors_caller(request: Request) -> Response:
        return await cors(request, origins=origins)

    @app.post(cors_path)
    async def cors_caller_post(request: Request) -> Response:
        return await cors(request, origins=origins, method="POST")

    if setup_with_no_url_param:
        @app.get("/{mistaken_relative:path}")
        async def cors_caller_for_relative(request: Request, mistaken_relative: str, _last_requested: Annotated[str, Cookie(...)]) -> RedirectResponse:
            x = Requester(str(request.url))
            x = x.query_string(x.query_params)
            resp = RedirectResponse(f"/cors?url={_last_requested}/{mistaken_relative}{'&' + x if x else ''}")
            return resp

        @app.post("/{mistaken_relative:path}")
        async def cors_caller_for_relative(request: Request, mistaken_relative: str,
                                           _last_requested: Annotated[str, Cookie(...)]) -> RedirectResponse:
            x = Requester(str(request.url))
            x = x.query_string(x.query_params)
            resp = RedirectResponse(f"/cors?url={_last_requested}/{mistaken_relative}{'&' + x if x else ''}")
            return resp

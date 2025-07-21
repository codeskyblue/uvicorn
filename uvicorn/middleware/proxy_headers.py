"""
This middleware can be used when a known proxy is fronting the application,
and is trusted to be properly setting the `X-Forwarded-Proto`,
`X-Forwarded-For` and `X-Forwarded-Host` headers with the connecting client information.

Modifies the `client`, `host` and `scheme` information so that they reference
the connecting client, rather that the connecting proxy.

https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#Proxies
"""
from typing import List, Optional, Tuple, Union
from starlette.types import ASGIApp, Receive, Scope, Send

class ProxyHeadersMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        trusted_hosts: Union[List[str], str] = "127.0.0.1",
    ) -> None:
        self.app = app
        if isinstance(trusted_hosts, str):
            self.trusted_hosts = {item.strip() for item in trusted_hosts.split(",")}
        else:
            self.trusted_hosts = set(trusted_hosts)
        self.always_trust = "*" in self.trusted_hosts

    def get_trusted_client_host(
        self, x_forwarded_for_hosts: List[str]
    ) -> Optional[str]:
        if self.always_trust:
            return x_forwarded_for_hosts[0]

        for host in reversed(x_forwarded_for_hosts):
            if host not in self.trusted_hosts:
                return host

        return None

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] in ("http", "websocket"):
            client_addr: Optional[Tuple[str, int]] = scope.get("client")
            client_host = client_addr[0] if client_addr else None

            if self.always_trust or client_host in self.trusted_hosts:
                headers = dict(scope["headers"])

                if b"x-forwarded-proto" in headers:
                    # Determine if the incoming request was http or https based on
                    # the X-Forwarded-Proto header.
                    x_forwarded_proto = (
                        headers[b"x-forwarded-proto"].decode("latin1").strip()
                    )
                    if scope["type"] == "websocket":
                        scope["scheme"] = (
                            "wss" if x_forwarded_proto == "https" else "ws"
                        )
                    else:
                        scope["scheme"] = x_forwarded_proto

                if b"x-forwarded-for" in headers:
                    # Determine the client address from the last trusted IP in the
                    # X-Forwarded-For header. We've lost the connecting client's port
                    # information by now, so only include the host.
                    x_forwarded_for = headers[b"x-forwarded-for"].decode("latin1")
                    x_forwarded_for_hosts = [
                        item.strip() for item in x_forwarded_for.split(",")
                    ]
                    host = self.get_trusted_client_host(x_forwarded_for_hosts)
                    port = 0
                    scope["client"] = (host, port)  # type: ignore[arg-type]
                    
                if b"x-forwarded-host" in headers:
                    x_forwarded_host = headers[b"x-forwarded-host"]
                    scope_headers = list(scope['headers'])
                    scope_headers = [(k, v) for k, v in scope_headers if k.lower() != b'host']
                    scope_headers.append((b'host', x_forwarded_host))
                    scope['headers'] = scope_headers
                    
        return await self.app(scope, receive, send)

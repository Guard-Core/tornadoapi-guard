import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# The parent serves requests (its regex worker threads start), pauses, and forks;
# the child serves the same requests through the same app. A fresh interpreter keeps
# the test process, with its own threads and loop, from being forked.
_SCRIPT = """
import ast, asyncio, os, time, logging, warnings
warnings.simplefilter("ignore"); logging.disable(logging.CRITICAL)
import tornado.httpserver, tornado.netutil, tornado.web
from guard_core.models import SecurityConfig
from guard_core.handlers.suspatterns_handler import active_sus_patterns
from tornadoapi_guard import SecurityHandler, SecurityMiddleware

class Probe(SecurityHandler):
    async def get(self):
        self.write("REACHED")

middleware = SecurityMiddleware(
    config=SecurityConfig(
        enable_redis=False, enable_rate_limiting=False, enable_ip_banning=False
    )
)
app = tornado.web.Application([(r"/p", Probe)], security_middleware=middleware)
texts = ("hello+world", "zz-foo12bar-zz", "x%27+UNION+SELECT+password+FROM+users--")

async def statuses():
    await middleware.initialize()
    sockets = tornado.netutil.bind_sockets(0, "127.0.0.1")
    server = tornado.httpserver.HTTPServer(app)
    server.add_sockets(sockets)
    port = sockets[0].getsockname()[1]
    answers = []
    for text in texts:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        head = f"GET /p?q={text} HTTP/1.1\\r\\nHost: h\\r\\nConnection: close"
        writer.write((head + "\\r\\n\\r\\n").encode())
        await writer.drain()
        answers.append(int((await reader.read()).split(b" ", 2)[1]))
        writer.close()
    server.stop()
    return answers

asyncio.run(statuses())
asyncio.run(active_sus_patterns().add_pattern(r"foo\\d+bar", True))
parent = asyncio.run(statuses())
time.sleep(0.3)
reader, writer = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(reader)
    os.write(writer, repr(asyncio.run(statuses())).encode())
    os._exit(0)
os.close(writer)
child = ast.literal_eval(os.read(reader, 65536).decode())
os.waitpid(pid, 0)
print(repr((parent, child)))
"""


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
def test_a_forked_worker_answers_its_first_requests_like_its_parent() -> None:
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{REPO_ROOT}{os.pathsep}{env.get('PYTHONPATH', '')}"
    result = subprocess.run(
        [sys.executable, "-W", "ignore", "-c", _SCRIPT],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=True,
    )
    parent, child = ast.literal_eval(result.stdout.strip().splitlines()[-1])

    assert parent[0] == 200
    assert parent[1:] == [400, 400]
    assert child == parent

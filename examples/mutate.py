# Break one guard at a time in a copy of the tree and check that `go test` fails.
# Usage: python3 examples/mutate.py .   (a few minutes; runs under nice)
import shutil, subprocess, sys, os, tempfile
SRC = os.path.abspath(sys.argv[1])
D, K, S, R, E = "mixnet/dialer.go", "keyring/keyring.go", "source/source.go", "refresh/refresh.go", "nym/ephemeral.go"
M = [
 # transport: the mixnet and nothing else
 ("direct dial instead of SOCKS5", D, "conn, err := dialSocks(ctx, d.Proxy, host, port, d.timeout())", "conn, err := (&net.Dialer{}).DialContext(ctx, \"tcp\", net.JoinHostPort(host, fmt.Sprint(port)))"),
 ("User-Agent sent", S, 'req.Header["User-Agent"] = []string{""}', 'req.Header["User-Agent"] = []string{"nymkeys/0.1"}'),
 ("plain-http redirect followed", S, 'if req.URL.Scheme != "https" {', "if false {"),
 ("plain-http keyserver URL allowed", S, 'if !strings.HasPrefix(u, "https://") {', "if false {"),
 # what gets into the keyring
 ("answers not checked at all", R, "if _, cerr := r.Check(k.Fingerprint, data); cerr != nil {", "if cerr := error(nil); cerr != nil {"),
 ("extra keys in an answer allowed", R, "\tif len(others) > 0 {", "\tif false {"),
 ("merge-only dropped", K, '"merge-only,self-sigs-only", "--import")', '"self-sigs-only", "--import")'),
 ("third-party certifications kept", K, '"merge-only,self-sigs-only", "--import")', '"merge-only", "--import")'),
 ("no size cap", S, "if int64(len(b)) > maxBytes {", "if false {"),
 ("revocation not reported", R, "if !a.Revoked() && b.Revoked() {", "if false {"),
 # unlinkability
 ("keys refreshed in keyring order", R, "order := Shuffle(keys, rng)", "order := keys"),
 ("no wait before a key", R, "if err := sleep(ctx, gaps[i]); err != nil {", "if err := sleep(ctx, 0); err != nil {"),
 ("fixed gaps instead of exponential", R, "out[i] = time.Duration(Exp(rng) * mean)", "out[i] = time.Duration(mean)"),
 ("ephemeral client shares the user's HOME", E, 'env := append(cleanEnv(os.Environ()), "HOME="+dir)', "env := os.Environ()"),
 ("ephemeral identity not deleted", E, "_ = os.RemoveAll(e.dir)", "_ = e.dir"),
 ("ephemeral client without reply SURBs", E, '"--use-reply-surbs", "true"', '"--use-reply-surbs", "false"'),
 ("proxy env passed to the Nym client", E, 'case "HOME", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY":', 'case "HOME":'),
 ("no cap on the WKD advanced request", "source/source.go", "rctx, cancel = context.WithTimeout(ctx, t)", "rctx, cancel = context.WithTimeout(ctx, t+time.Minute)"),
 ("skipped source counted as an answer", "refresh/refresh.go", "sr.Error = source.ErrSkipped.Error()\n", "sr.Error = source.ErrSkipped.Error()\n\t\t\tanyAnswer = true\n"),
 ("no retry when nothing answered", "refresh/refresh.go", "if !res.retry || attempt > r.Retries || ctx.Err() != nil {", "if true {"),
 ("daemon refreshes revoked keys", "refresh/refresh.go", "if err != nil || r.IncludeRevoked {", "if true {"),
 ("dead advanced host reported as an error", "source/source.go", "advErr = msg\n\t\t\t\tcontinue", "errs = append(errs, msg)\n\t\t\t\tcontinue"),
]
# Run the tests with a throwaway $HOME, so a mutation that leaks the real
# HOME to a child process can't write into the user's ~/.nym.
GOENV = {k: subprocess.run(["go", "env", k], capture_output=True, text=True).stdout.strip()
         for k in ("GOCACHE", "GOMODCACHE", "GOPATH")}
results = []
for name, f, old, new in M:
    tmp = tempfile.mkdtemp(prefix="nymkeys-mut-")
    dst = os.path.join(tmp, "src")
    shutil.copytree(SRC, dst, ignore=shutil.ignore_patterns(".git", "examples"))
    p = os.path.join(dst, f)
    s = open(p).read()
    if s.count(old) != 1:
        results.append((name, "ANCHOR NOT FOUND (%d)" % s.count(old))); shutil.rmtree(tmp); continue
    s = s.replace(old, new)
    if "net.Dialer{}" in new and '"net"' not in s:
        s = s.replace('import (\n', 'import (\n\t"net"\n', 1)
    open(p, "w").write(s)
    env = dict(os.environ, HOME=os.path.join(tmp, "home"), **GOENV)
    os.mkdir(env["HOME"])
    r = subprocess.run(["nice", "-n", "19", "go", "test", "-count=1", "./..."], cwd=dst, env=env, capture_output=True, text=True, timeout=300)
    out = r.stdout + r.stderr
    if r.returncode == 0:
        verdict = "SURVIVED (no test failed)"
    elif "build failed" in out or "[build failed]" in out or "setup failed" in out:
        verdict = "BUILD FAILED (mutation invalid): " + out[:300].replace("\n", " | ")
    else:
        fails = sorted({l.split()[2] for l in out.splitlines() if l.strip().startswith("--- FAIL")})
        verdict = "caught by " + ", ".join(fails) if fails else "caught (panic/timeout): " + out[-200:].replace("\n", " | ")
    results.append((name, verdict))
    shutil.rmtree(tmp)
for n, v in results:
    print(f"{n:42s} {v}")
print(f"{sum(v.startswith('caught') for _, v in results)} of {len(results)} mutations caught")

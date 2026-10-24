/* 浄衛 Jōei :: USERS (admin only) */

const PW_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

// 20 characters of A–Z a–z 0–9 from crypto.getRandomValues. Bytes at or above
// 248 (the largest multiple of 62 that fits a byte) are rejected so every
// character is equally likely.
function generatePassword(len = 20) {
  const limit = 256 - (256 % PW_ALPHABET.length);
  let out = "";
  while (out.length < len) {
    const buf = new Uint8Array(len * 2);
    crypto.getRandomValues(buf);
    for (let i = 0; i < buf.length && out.length < len; i++) {
      if (buf[i] < limit) out += PW_ALPHABET[buf[i] % PW_ALPHABET.length];
    }
  }
  return out;
}

const USER_ERRORS = {
  user_exists: "A user with this name already exists",
  last_admin: "At least one enabled admin must remain",
  self: "You can't do this to your own account",
};

const HTTP_TEXT = {
  400: "400 Bad Request", 403: "403 Forbidden", 404: "404 Not Found", 409: "409 Conflict",
  413: "413 Payload Too Large", 500: "500 Internal Server Error", 503: "503 Service Unavailable",
};

function userErrorText(err) {
  if (err.code && USER_ERRORS[err.code]) return USER_ERRORS[err.code];
  if (err.code === "user_not_found") return "This user no longer exists";
  if (err.code === "users_unavailable") return "User management is not available on this server";
  return String(err.message || err); // invalid_user → the server's message
}

function userStatus(u) {
  if (u.disabled) return { text: "disabled", color: "var(--washi-faint)" };
  if (u.must_change_password) return { text: "must change password", color: "var(--gold-l)" };
  return { text: "active", color: "var(--jade-l)" };
}

function fmtWhen(iso) {
  if (!iso) return "never";
  const d = new Date(iso);
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

/* ---------- dialog shell (same approach as ChangePasswordModal) ---------- */
function UserDialog({ title, onClose, children }) {
  useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <>
      <div className="scrim" onClick={onClose}></div>
      <div role="dialog" aria-modal="true" aria-label={title}
        style={{ position: "fixed", inset: 0, zIndex: 41, display: "grid", placeItems: "center", padding: 24, pointerEvents: "none" }}>
        <div className="card login-card" style={{ pointerEvents: "auto" }}>
          <div className="row">
            <div style={{ fontSize: 15, fontWeight: 600 }}>{title}</div>
            <button className="x-btn right" style={{ width: 24, height: 24 }} onClick={onClose} aria-label="close"><Icons.x /></button>
          </div>
          {children}
        </div>
      </div>
    </>
  );
}

/* ---------- temporary password field with Generate ---------- */
function TempPasswordField({ value, onChange, disabled, autoFocus }) {
  return (
    <div className="field">
      <label>Temporary password</label>
      <div className="row" style={{ gap: 8 }}>
        <input className="input mono" style={{ flex: 1, minWidth: 0 }} value={value} autoFocus={autoFocus}
          onChange={(e) => onChange(e.target.value)} autoComplete="new-password" spellCheck={false} disabled={disabled} />
        <button type="button" className="btn sm" onClick={() => onChange(generatePassword())} disabled={disabled}>Generate</button>
      </div>
      <div className="hint">At least 12 characters, and not the login.</div>
    </div>
  );
}

/* ---------- the password, shown once after create/reset ---------- */
function ShownOnce({ shown, onDismiss }) {
  const ref = useRef(null);
  const [copied, setCopied] = useState(false);
  const copy = () => {
    const done = () => { setCopied(true); setTimeout(() => setCopied(false), 1500); };
    // The Clipboard API needs a secure context; plain-HTTP consoles fall back
    // to selecting the field and the legacy copy command.
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(shown.password).then(done, () => {});
      return;
    }
    if (ref.current) {
      ref.current.select();
      try { if (document.execCommand("copy")) done(); } catch (_) { /* leave it selected for a manual copy */ }
    }
  };
  return (
    <div className="card" role="status" style={{ padding: 18, marginBottom: 16, borderColor: "var(--gold)" }}>
      <div className="row" style={{ marginBottom: 10 }}>
        <div style={{ fontSize: 13.5, fontWeight: 600 }}>
          Temporary password for <span className="mono">{shown.username}</span>
        </div>
        <button className="x-btn right" style={{ width: 24, height: 24 }} onClick={onDismiss} aria-label="dismiss"><Icons.x /></button>
      </div>
      <div className="row" style={{ gap: 8 }}>
        <input ref={ref} className="input mono" readOnly value={shown.password} style={{ flex: 1, minWidth: 0 }}
          onFocus={(e) => e.target.select()} />
        <button className="btn sm" onClick={copy}>{copied ? "Copied" : "Copy"}</button>
      </div>
      <div className="faint" style={{ fontSize: 11.5, marginTop: 8 }}>Shown once. The user sets their own at first sign-in.</div>
    </div>
  );
}

/* ---------- add user ---------- */
function AddUserForm({ onCreated, onCancel, onError }) {
  const [username, setUsername] = useState("");
  const [role, setRole] = useState("operator");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);

  const ready = username.trim() && password;
  const submit = (e) => {
    e.preventDefault();
    if (busy || !ready) return;
    setBusy(true);
    const name = username.trim();
    JOEI.createUser({ username: name, role, password })
      .then((u) => onCreated(u, password))
      .catch(onError)
      .finally(() => setBusy(false));
  };

  return (
    <form className="card" onSubmit={submit} style={{ padding: 22, marginBottom: 16, display: "flex", flexDirection: "column", gap: 16 }}>
      <div style={{ fontSize: 15, fontWeight: 600 }}>Add user</div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, alignItems: "start" }}>
        <div className="field">
          <label>Login</label>
          <input className="input" value={username} onChange={(e) => setUsername(e.target.value)}
            autoFocus autoComplete="off" spellCheck={false} maxLength={64} disabled={busy} />
          <div className="hint">Letters, digits and <span className="mono">. _ @ -</span>, up to 64.</div>
        </div>
        <div className="field">
          <label>Role</label>
          <div className="seg-radio" role="radiogroup">
            {["operator", "admin"].map((r) => (
              <button type="button" key={r} role="radio" aria-checked={role === r}
                className={role === r ? "active" : ""} onClick={() => setRole(r)} disabled={busy}>{r}</button>
            ))}
          </div>
          <div className="hint">{role === "admin" ? "Full access, including users and settings." : "Day-to-day work: lists and quarantine decisions."}</div>
        </div>
      </div>
      <TempPasswordField value={password} onChange={setPassword} disabled={busy} />
      <div className="row" style={{ gap: 10, justifyContent: "flex-end" }}>
        <button type="button" className="btn ghost" onClick={onCancel} disabled={busy}>Cancel</button>
        <button type="submit" className="btn primary" disabled={busy || !ready}>{busy ? "Creating…" : "Create user"}</button>
      </div>
    </form>
  );
}

/* ---------- per-row ⋯ menu ---------- */
// On the signed-in admin's own row the menu holds only a hint: the server
// refuses self role/disable/delete (409 self), and resetting your own password
// here would sign you out — "Change password" in the sidebar is the way.
function RowMenu({ user, self, onAction }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  useEffect(() => {
    if (!open) return;
    const close = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    const onKey = (e) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", close);
    window.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("mousedown", close); window.removeEventListener("keydown", onKey); };
  }, [open]);

  const other = user.role === "admin" ? "operator" : "admin";
  const items = self ? [] : [
    { id: "role", label: <>Change role <span className="faint">→ {other}</span></> },
    { id: "reset", label: "Reset password" },
    { id: user.disabled ? "enable" : "disable", label: user.disabled ? "Enable" : "Disable" },
    { id: "delete", label: "Delete", danger: true },
  ];
  return (
    <div ref={ref} style={{ position: "relative", justifySelf: "end" }}>
      <button className="btn sm ghost" aria-haspopup="menu" aria-expanded={open} aria-label={`actions for ${user.username}`}
        onClick={() => setOpen(!open)} style={{ padding: "2px 8px", letterSpacing: ".1em" }}>⋯</button>
      {open && (
        <div role="menu" className="card"
          style={{ position: "absolute", right: 0, top: "calc(100% + 4px)", zIndex: 20, minWidth: 190, padding: 4, display: "flex", flexDirection: "column" }}>
          {self && (
            <div className="faint" role="note" style={{ fontSize: 11.5, padding: "6px 8px", lineHeight: 1.45 }}>
              This is you. Use <b style={{ color: "var(--washi-soft)" }}>Change password</b> in the sidebar;
              another admin can change your role or status.
            </div>
          )}
          {items.map((it) => (
            <button key={it.id} role="menuitem" className="btn sm ghost"
              style={{ justifyContent: "flex-start", textAlign: "left", border: "none", ...(it.danger ? { color: "var(--vermilion-l)" } : {}) }}
              onClick={() => { setOpen(false); onAction(it.id, user); }}>{it.label}</button>
          ))}
        </div>
      )}
    </div>
  );
}

function ResetPasswordDialog({ user, onClose, onDone, onError }) {
  const [password, setPassword] = useState(generatePassword);
  const [busy, setBusy] = useState(false);
  const submit = (e) => {
    e.preventDefault();
    if (busy || !password) return;
    setBusy(true);
    JOEI.resetUserPassword(user.username, password)
      .then(() => onDone(password))
      .catch((err) => { setBusy(false); onError(err); });
  };
  return (
    <UserDialog title={`Reset password · ${user.username}`} onClose={onClose}>
      <form onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        <div className="faint" style={{ fontSize: 11.5, marginTop: -6 }}>
          Their sessions are signed out; they choose a new password at next sign-in.
        </div>
        <TempPasswordField value={password} onChange={setPassword} disabled={busy} autoFocus />
        <div className="row" style={{ gap: 10 }}>
          <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="submit" className="btn primary" style={{ flex: 1 }} disabled={busy || !password}>
            {busy ? "Resetting…" : "Reset password"}
          </button>
        </div>
      </form>
    </UserDialog>
  );
}

function DeleteUserDialog({ user, onClose, onConfirm }) {
  const [busy, setBusy] = useState(false);
  const confirm = () => {
    setBusy(true);
    onConfirm().finally(() => setBusy(false));
  };
  return (
    <UserDialog title="Delete user" onClose={onClose}>
      <div className="muted" style={{ fontSize: 13 }}>
        Delete <b className="mono" style={{ color: "var(--washi)" }}>{user.username}</b>? Their sessions end immediately. This cannot be undone.
      </div>
      <div className="row" style={{ gap: 10 }}>
        <button className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
        <button className="btn primary" style={{ flex: 1 }} onClick={confirm} disabled={busy}>{busy ? "Deleting…" : "Delete"}</button>
      </div>
    </UserDialog>
  );
}

/* ---------- page ---------- */
function Users({ notify }) {
  const [list, setList] = useState(null); // null until the first load settles
  const [loadErr, setLoadErr] = useState("");
  const [adding, setAdding] = useState(false);
  const [shown, setShown] = useState(null); // { username, password } — displayed once
  const [resetFor, setResetFor] = useState(null);
  const [deleteFor, setDeleteFor] = useState(null);
  const [busyRow, setBusyRow] = useState("");

  const reload = useCallback(() => JOEI.listUsers()
    .then((xs) => { setList(xs); setLoadErr(""); })
    .catch((err) => { if (!JOEI.isAuthError(err)) setLoadErr(userErrorText(err)); }), []);
  useEffect(() => { reload(); }, [reload]);

  const fail = (title) => (err) => {
    if (JOEI.isAuthError(err)) return; // the shell already switched screens
    notify({ kind: "block", code: HTTP_TEXT[err.status] || `HTTP ${err.status}`, title, msg: userErrorText(err) });
    if (err.code === "user_not_found") reload();
  };

  const replace = (u) => setList((xs) => (xs || []).map((x) => (x.username === u.username ? u : x)));

  const onAction = (id, u) => {
    if (id === "reset") { setResetFor(u); return; }
    if (id === "delete") { setDeleteFor(u); return; }
    const change = id === "role" ? { role: u.role === "admin" ? "operator" : "admin" } : { disabled: id === "disable" };
    setBusyRow(u.username);
    JOEI.updateUser(u.username, change)
      .then((nu) => {
        replace(nu);
        notify(id === "role"
          ? { kind: "ok", code: "200 OK", title: "Role changed", msg: <><span className="t-pkg">{nu.username}</span> is now {nu.role}.</> }
          : { kind: "ok", code: "200 OK", title: nu.disabled ? "User disabled" : "User enabled",
              msg: <><span className="t-pkg">{nu.username}</span> {nu.disabled ? "can no longer sign in; open sessions end on their next request." : "can sign in again."}</> });
      })
      .catch(fail(id === "role" ? "Role change failed" : id === "disable" ? "Disable failed" : "Enable failed"))
      .finally(() => setBusyRow(""));
  };

  const me = JOEI.username.toLowerCase();
  const cols = { gridTemplateColumns: "minmax(0, 1fr) 110px 180px 150px 48px" };

  return (
    <div className="content-inner">
      <div className="section-head">
        <span className="head-kanji kanji">人</span>
        <div>
          <div className="eyebrow">Console accounts · changes apply immediately</div>
          <h2>Users</h2>
        </div>
        <div className="spacer"></div>
        {!adding && <button className="btn primary" onClick={() => { setAdding(true); setShown(null); }}><Icons.plus /> Add user</button>}
      </div>

      {shown && <ShownOnce shown={shown} onDismiss={() => setShown(null)} />}

      {adding && (
        <AddUserForm onCancel={() => setAdding(false)} onError={fail("User not created")}
          onCreated={(u, password) => {
            setAdding(false);
            setShown({ username: u.username, password });
            setList((xs) => [...(xs || []), u]);
            notify({ kind: "ok", code: "201 Created", title: "User created", msg: <><span className="t-pkg">{u.username}</span> · {u.role}</> });
          }} />
      )}

      <div className="card" style={{ padding: 0 }}>
        <div className="feed-row head" style={cols}>
          <span>Login</span><span>Role</span><span>Status</span><span>Last login</span><span></span>
        </div>
        {list === null && !loadErr && <div className="muted" style={{ padding: 18 }}>Loading…</div>}
        {loadErr && (
          <div className="row" style={{ padding: 18, gap: 12 }}>
            <span role="alert" style={{ color: "var(--vermilion-l)" }}>{loadErr}</span>
            <button className="btn sm" onClick={reload}>Retry</button>
          </div>
        )}
        {(list || []).map((u) => {
          const st = userStatus(u);
          const self = u.username.toLowerCase() === me;
          return (
            <div className="feed-row" key={u.username} style={{ ...cols, opacity: busyRow === u.username ? .5 : 1 }}>
              <span className="pkg">{u.username}{self && <span className="faint" style={{ fontFamily: "inherit", fontSize: 11.5 }}> · you</span>}</span>
              <span style={{ fontSize: 12.5, color: u.role === "admin" ? "var(--gold-l)" : "var(--washi-soft)" }}>{u.role}</span>
              <span style={{ fontSize: 12.5, color: st.color }}>{st.text}</span>
              <span className="ts">{fmtWhen(u.last_login_at)}</span>
              <RowMenu user={u} self={self} onAction={onAction} />
            </div>
          );
        })}
      </div>

      {resetFor && (
        <ResetPasswordDialog user={resetFor} onClose={() => setResetFor(null)} onError={fail("Password reset failed")}
          onDone={(password) => {
            const name = resetFor.username;
            setResetFor(null);
            setAdding(false);
            setShown({ username: name, password });
            setList((xs) => (xs || []).map((x) => (x.username === name ? { ...x, must_change_password: true } : x)));
            notify({ kind: "ok", code: "204 No Content", title: "Password reset", msg: <><span className="t-pkg">{name}</span> must choose a new password at sign-in.</> });
          }} />
      )}

      {deleteFor && (
        <DeleteUserDialog user={deleteFor} onClose={() => setDeleteFor(null)}
          onConfirm={() => JOEI.deleteUser(deleteFor.username)
            .then(() => {
              const name = deleteFor.username;
              setDeleteFor(null);
              setList((xs) => (xs || []).filter((x) => x.username !== name));
              notify({ kind: "ok", code: "204 No Content", title: "User deleted", msg: <><span className="t-pkg">{name}</span> was removed.</> });
            })
            .catch((err) => { setDeleteFor(null); fail("Delete failed")(err); })} />
      )}
    </div>
  );
}

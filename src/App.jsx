import React, { useState, useCallback, useRef, useEffect } from "react";

// ─── AES-GCM encrypt / decrypt helpers ───
async function deriveKey(password) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: enc.encode("nfc-verify-salt-2024"), iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptPayload(plaintext, password) {
  const key = await deriveKey(password);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const cipherBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext));
  const combined = new Uint8Array(iv.length + cipherBuf.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(cipherBuf), iv.length);
  return btoa(String.fromCharCode(...combined));
}

async function decryptPayload(base64, password) {
  const key = await deriveKey(password);
  const raw = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
  const iv = raw.slice(0, 12);
  const cipher = raw.slice(12);
  const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
  return new TextDecoder().decode(plainBuf);
}

// ─── Particles ───
function Particles() {
  const particles = useRef(
    Array.from({ length: 18 }, (_, i) => ({
      size: 4 + Math.random() * 8,
      left: Math.random() * 100,
      delay: Math.random() * 12,
      dur: 14 + Math.random() * 18,
      opacity: 0.08 + Math.random() * 0.12,
      color: i % 3 === 0 ? "#6ee7b7" : i % 3 === 1 ? "#818cf8" : "#f9a8d4",
    }))
  ).current;

  return (
    <div style={{ position: "fixed", inset: 0, pointerEvents: "none", zIndex: 0, overflow: "hidden" }}>
      {particles.map((p, i) => (
        <div key={i} style={{
          position: "absolute", width: p.size, height: p.size, borderRadius: "50%",
          background: p.color, opacity: p.opacity, left: `${p.left}%`, bottom: "-20px",
          animation: `floatUp ${p.dur}s ${p.delay}s linear infinite`,
        }} />
      ))}
      <style>{`
        @keyframes floatUp {
          0%   { transform: translateY(0) scale(1); opacity: 0; }
          10%  { opacity: 1; }
          90%  { opacity: 1; }
          100% { transform: translateY(-110vh) scale(0.4); opacity: 0; }
        }
      `}</style>
    </div>
  );
}

// ─── PulseRing ───
function PulseRing({ active, color = "#6ee7b7" }) {
  if (!active) return null;
  return (
    <div style={{ position: "relative", width: 120, height: 120, margin: "0 auto" }}>
      {[0, 1, 2].map(i => (
        <div key={i} style={{
          position: "absolute", inset: 0, borderRadius: "50%",
          border: `2px solid ${color}`, opacity: 0,
          animation: `pulseRing 2s ${i * 0.6}s ease-out infinite`,
        }} />
      ))}
      <div style={{
        position: "absolute", inset: 20, borderRadius: "50%",
        background: `radial-gradient(circle, ${color}22, ${color}08)`,
        display: "flex", alignItems: "center", justifyContent: "center",
      }}>
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5">
          <path d="M6 8.32a7.43 7.43 0 0 1 0 7.36" />
          <path d="M9.46 6.21a11.76 11.76 0 0 1 0 11.58" />
          <path d="M12.91 4.1a16.07 16.07 0 0 1 0 15.8" />
          <path d="M16.37 2a20.4 20.4 0 0 1 0 20" />
        </svg>
      </div>
      <style>{`
        @keyframes pulseRing {
          0%   { transform: scale(0.8); opacity: 0.7; }
          100% { transform: scale(1.8); opacity: 0; }
        }
      `}</style>
    </div>
  );
}

// ─── StatusBadge ───
function StatusBadge({ type, children }) {
  const colors = {
    success: { bg: "#06331f", border: "#6ee7b7", text: "#6ee7b7", icon: "✓" },
    error:   { bg: "#331111", border: "#f87171", text: "#f87171", icon: "✕" },
    info:    { bg: "#0c1a33", border: "#818cf8", text: "#93a3f8", icon: "ℹ" },
    warning: { bg: "#332b0c", border: "#fbbf24", text: "#fcd34d", icon: "⚠" },
  };
  const c = colors[type] || colors.info;
  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 10, padding: "12px 16px",
      background: c.bg, border: `1px solid ${c.border}33`, borderRadius: 12,
      fontSize: 14, color: c.text, lineHeight: 1.5,
      animation: "fadeSlideIn 0.3s ease-out",
    }}>
      <span style={{ fontSize: 18, flexShrink: 0 }}>{c.icon}</span>
      <span>{children}</span>
    </div>
  );
}

const isNFCSupported = typeof window !== "undefined" && "NDEFReader" in window;

// ─── Main App ───
export default function NFCVerifyApp() {
  const [mode, setMode] = useState("verify");
  const [password, setPassword] = useState("mySecurePass123");
  const [showPassword, setShowPassword] = useState(false);
  const [content, setContent] = useState("");
  const [status, setStatus] = useState(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [scannedValue, setScannedValue] = useState(null);
  const [verificationResult, setVerificationResult] = useState(null);
  const abortRef = useRef(null);

  useEffect(() => {
    return () => { if (abortRef.current) abortRef.current.abort(); };
  }, [mode]);

  const resetState = () => {
    setStatus(null);
    setScannedValue(null);
    setVerificationResult(null);
    if (abortRef.current) { abortRef.current.abort(); abortRef.current = null; }
    setIsProcessing(false);
  };

  const handleWrite = useCallback(async () => {
    if (!content.trim()) { setStatus({ type: "warning", message: "Enter content to write." }); return; }
    if (!password.trim()) { setStatus({ type: "warning", message: "Password is required." }); return; }
    if (!isNFCSupported) { setStatus({ type: "error", message: "Web NFC not supported. Use Chrome on Android." }); return; }
    try {
      setIsProcessing(true);
      setStatus({ type: "info", message: "Encrypting content…" });
      const encrypted = await encryptPayload(content, password);
      setStatus({ type: "info", message: "Hold your NFC tag near the device…" });
      const ndef = new window.NDEFReader();
      abortRef.current = new AbortController();
      await ndef.write(
        { records: [{ recordType: "text", data: `NFCV:${encrypted}` }] },
        { signal: abortRef.current.signal }
      );
      setStatus({ type: "success", message: "Tag written successfully!" });
      setContent("");
    } catch (err) {
      if (err.name !== "AbortError") setStatus({ type: "error", message: `Write failed: ${err.message}` });
    } finally {
      setIsProcessing(false);
    }
  }, [content, password]);

  const handleVerify = useCallback(async () => {
    if (!password.trim()) { setStatus({ type: "warning", message: "Password is required." }); return; }
    if (!isNFCSupported) { setStatus({ type: "error", message: "Web NFC not supported. Use Chrome on Android." }); return; }
    try {
      setIsProcessing(true);
      setScannedValue(null);
      setVerificationResult(null);
      setStatus({ type: "info", message: "Scanning… hold the NFC tag near your device." });
      const ndef = new window.NDEFReader();
      abortRef.current = new AbortController();
      ndef.addEventListener("reading", async ({ message }) => {
        try {
          let rawText = "";
          for (const record of message.records) {
            if (record.recordType === "text") {
              rawText = new TextDecoder(record.encoding || "utf-8").decode(record.data);
              break;
            }
          }
          if (!rawText.startsWith("NFCV:")) {
            setVerificationResult("invalid");
            setScannedValue(rawText || "(empty tag)");
            setStatus({ type: "error", message: "Not a valid NFC-Verify protected tag." });
            setIsProcessing(false);
            abortRef.current?.abort();
            return;
          }
          const decrypted = await decryptPayload(rawText.slice(5), password);
          setScannedValue(decrypted);
          setVerificationResult("valid");
          setStatus({ type: "success", message: "Tag verified! Content decrypted successfully." });
        } catch {
          setVerificationResult("invalid");
          setScannedValue(null);
          setStatus({ type: "error", message: "Decryption failed — wrong password or corrupted data." });
        } finally {
          setIsProcessing(false);
          abortRef.current?.abort();
        }
      }, { signal: abortRef.current.signal });
      await ndef.scan({ signal: abortRef.current.signal });
    } catch (err) {
      if (err.name !== "AbortError") {
        setStatus({ type: "error", message: `Scan failed: ${err.message}` });
        setIsProcessing(false);
      }
    }
  }, [password]);

  const handleCancel = () => {
    if (abortRef.current) abortRef.current.abort();
    setIsProcessing(false);
    setStatus({ type: "info", message: "Operation cancelled." });
  };

  // ─── Styles ───
  const tabBtnStyle = (active) => ({
    flex: 1, padding: "12px 0", borderRadius: 10, fontSize: 14, fontWeight: 600,
    letterSpacing: "0.02em", cursor: "pointer", transition: "all 0.25s ease",
    background: active ? "linear-gradient(135deg, #6ee7b733, #818cf822)" : "transparent",
    color: active ? "#e2e8f0" : "#64748b",
    border: active ? "1px solid #6ee7b744" : "1px solid transparent",
  });

  const inputStyle = {
    width: "100%", padding: "14px 16px", background: "#111827",
    border: "1px solid #1e293b", borderRadius: 12, color: "#e2e8f0",
    fontSize: 15, outline: "none", transition: "border-color 0.2s",
    boxSizing: "border-box", fontFamily: "inherit",
  };

  const btnPrimary = (color = "#6ee7b7") => ({
    width: "100%", padding: "16px", border: "none", borderRadius: 14,
    fontSize: 16, fontWeight: 700, letterSpacing: "0.02em", cursor: "pointer",
    color: "#0a0e1a", background: `linear-gradient(135deg, ${color}, ${color}bb)`,
    boxShadow: `0 4px 24px ${color}33`, transition: "all 0.25s ease", fontFamily: "inherit",
  });

  const btnCancel = {
    width: "100%", padding: "16px", borderRadius: 14, fontSize: 16, fontWeight: 700,
    cursor: "pointer", background: "#f8717133", color: "#f87171",
    boxShadow: "none", border: "1px solid #f8717144", fontFamily: "inherit",
    letterSpacing: "0.02em", transition: "all 0.25s ease",
  };

  return (
    <div style={{ minHeight: "100vh", background: "#0a0e1a", fontFamily: "'DM Sans', system-ui, sans-serif", color: "#e2e8f0", position: "relative", overflow: "hidden" }}>
      <Particles />

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
        @keyframes fadeSlideIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
        input:focus, textarea:focus { border-color: #6ee7b7 !important; }
        button:hover { transform: translateY(-1px); filter: brightness(1.08); }
        button:active { transform: translateY(0px); }
        * { box-sizing: border-box; }
      `}</style>

      <div style={{ position: "relative", zIndex: 1, maxWidth: 480, margin: "0 auto", padding: "24px 20px 40px" }}>

        {/* Header */}
        <div style={{ textAlign: "center", marginBottom: 32, paddingTop: 20 }}>
          <div style={{
            width: 56, height: 56, margin: "0 auto 16px", borderRadius: 16,
            display: "flex", alignItems: "center", justifyContent: "center",
            background: "linear-gradient(135deg, #6ee7b722, #818cf822)",
            border: "1px solid #6ee7b733",
          }}>
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#6ee7b7" strokeWidth="1.5" strokeLinecap="round">
              <rect x="2" y="6" width="20" height="12" rx="3" />
              <path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
              <circle cx="12" cy="12" r="2" />
              <path d="M9.5 12a2.5 2.5 0 0 1 5 0" opacity="0.5" />
            </svg>
          </div>
          <h1 style={{
            fontSize: 26, fontWeight: 700, margin: "0 0 6px",
            background: "linear-gradient(135deg, #e2e8f0, #94a3b8)",
            WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
          }}>NFC Verify</h1>
          <p style={{ fontSize: 14, color: "#64748b", margin: 0 }}>Password-protected NFC tag verification</p>
        </div>

        {/* Tabs */}
        <div style={{ display: "flex", gap: 6, padding: 4, background: "#111827", borderRadius: 14, marginBottom: 28, border: "1px solid #1e293b" }}>
          <button style={tabBtnStyle(mode === "verify")} onClick={() => { setMode("verify"); resetState(); }}>🔍 &nbsp;Verify Tag</button>
          <button style={tabBtnStyle(mode === "write")} onClick={() => { setMode("write"); resetState(); }}>✏️ &nbsp;Write Tag</button>
        </div>

        {/* Password */}
        <div style={{ marginBottom: 24 }}>
          <label style={{ display: "block", fontSize: 13, fontWeight: 600, color: "#94a3b8", marginBottom: 8, letterSpacing: "0.04em", textTransform: "uppercase" }}>
            🔐 Encryption Password
          </label>
          <div style={{ position: "relative" }}>
            <input
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="Enter password…"
              style={{ ...inputStyle, paddingRight: 48, fontFamily: "'JetBrains Mono', monospace", fontSize: 14 }}
            />
            <button
              onClick={() => setShowPassword(!showPassword)}
              style={{ position: "absolute", right: 8, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", color: "#64748b", cursor: "pointer", fontSize: 18, padding: 6 }}
            >
              {showPassword ? "🙈" : "👁️"}
            </button>
          </div>
          <p style={{ fontSize: 12, color: "#475569", margin: "6px 0 0", lineHeight: 1.4 }}>
            Keep this consistent between write &amp; verify.
          </p>
        </div>

        {/* Write Mode */}
        {mode === "write" && (
          <div style={{ animation: "fadeSlideIn 0.35s ease-out" }}>
            <div style={{ marginBottom: 24 }}>
              <label style={{ display: "block", fontSize: 13, fontWeight: 600, color: "#94a3b8", marginBottom: 8, letterSpacing: "0.04em", textTransform: "uppercase" }}>
                📝 Content to Write
              </label>
              <textarea
                value={content}
                onChange={e => setContent(e.target.value)}
                placeholder="Enter text, URL, serial number, ID…"
                rows={4}
                style={{ ...inputStyle, resize: "vertical", lineHeight: 1.6 }}
              />
            </div>
            {isProcessing && <PulseRing active color="#818cf8" />}
            <div style={{ marginTop: 20 }}>
              {!isProcessing
                ? <button style={btnPrimary("#818cf8")} onClick={handleWrite}>Write to NFC Tag</button>
                : <button style={btnCancel} onClick={handleCancel}>Cancel</button>
              }
            </div>
          </div>
        )}

        {/* Verify Mode */}
        {mode === "verify" && (
          <div style={{ animation: "fadeSlideIn 0.35s ease-out" }}>
            {isProcessing && <div style={{ margin: "8px 0 24px" }}><PulseRing active color="#6ee7b7" /></div>}

            {verificationResult && (
              <div style={{
                padding: 20, borderRadius: 16, marginBottom: 24, animation: "fadeSlideIn 0.4s ease-out",
                background: verificationResult === "valid" ? "linear-gradient(135deg, #06331f, #0a1e2e)" : "linear-gradient(135deg, #331111, #1e0c0c)",
                border: `1px solid ${verificationResult === "valid" ? "#6ee7b733" : "#f8717133"}`,
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
                  <div style={{ width: 36, height: 36, borderRadius: 10, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20, background: verificationResult === "valid" ? "#6ee7b722" : "#f8717122" }}>
                    {verificationResult === "valid" ? "✅" : "❌"}
                  </div>
                  <div>
                    <div style={{ fontSize: 16, fontWeight: 700, color: verificationResult === "valid" ? "#6ee7b7" : "#f87171" }}>
                      {verificationResult === "valid" ? "Verified — Authentic" : "Verification Failed"}
                    </div>
                    <div style={{ fontSize: 12, color: "#64748b" }}>
                      {verificationResult === "valid" ? "Content decrypted successfully" : "Invalid tag or wrong password"}
                    </div>
                  </div>
                </div>
                {scannedValue && (
                  <div style={{ padding: "12px 14px", borderRadius: 10, background: "#0a0e1a", border: "1px solid #1e293b", fontFamily: "'JetBrains Mono', monospace", fontSize: 14, color: "#e2e8f0", lineHeight: 1.6, wordBreak: "break-all" }}>
                    {scannedValue}
                  </div>
                )}
              </div>
            )}

            <div style={{ marginTop: 8 }}>
              {!isProcessing
                ? <button style={btnPrimary("#6ee7b7")} onClick={handleVerify}>Scan &amp; Verify Tag</button>
                : <button style={btnCancel} onClick={handleCancel}>Cancel Scan</button>
              }
            </div>
          </div>
        )}

        {/* Status */}
        {status && <div style={{ marginTop: 20 }}><StatusBadge type={status.type}>{status.message}</StatusBadge></div>}

        {/* NFC Not Supported Warning */}
        {!isNFCSupported && (
          <div style={{ marginTop: 24, padding: 16, borderRadius: 12, background: "#1a1520", border: "1px solid #fbbf2433", fontSize: 13, color: "#fcd34d", lineHeight: 1.6, textAlign: "center" }}>
            <strong>Web NFC not available</strong><br />
            Use <strong>Chrome 89+</strong> on an <strong>Android</strong> device.
          </div>
        )}

        {/* Footer */}
        <div style={{ marginTop: 32, padding: "16px 20px", borderRadius: 14, background: "#111827", border: "1px solid #1e293b", fontSize: 13, color: "#475569", lineHeight: 1.7 }}>
          <div style={{ fontWeight: 600, color: "#94a3b8", marginBottom: 6 }}>How it works</div>
          <div><span style={{ color: "#818cf8" }}>Write</span> — AES-256 encrypts your content with the password and writes it to the tag.</div>
          <div><span style={{ color: "#6ee7b7" }}>Verify</span> — Scans the tag and decrypts it with the password to reveal the original content.</div>
          <div style={{ marginTop: 8, fontSize: 12, color: "#334155" }}>Only matching passwords can decrypt the data.</div>
        </div>

      </div>
    </div>
  );
}
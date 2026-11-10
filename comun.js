// Descifrado compartido por el registro y el verificador (mismo esquema que generar_zorzal.mjs).
const enc = new TextEncoder();
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const deB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function abrir(clave, sobre) {
  const [iv, datos] = sobre.split(".").map(deB64);
  const k = await crypto.subtle.importKey("raw", clave, "AES-GCM", false, ["decrypt"]);
  return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, k, datos)));
}

// PIN → ficha del invitado (o null)
async function fichaPorPin(pin) {
  const base = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveBits"]);
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: enc.encode(ZD.sal), iterations: ZD.iter }, base, 384));
  const sobre = ZD.registro[hex(bits.slice(0, 16))];
  return sobre ? abrir(bits.slice(16), sobre) : null;
}

// código del QR → invitado (o null)
async function fichaPorCodigo(codigo) {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode("id:" + codigo)));
  const sobre = ZD.puerta[hex(h.slice(0, 16))];
  if (!sobre) return null;
  const k = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode("k:" + codigo)));
  return abrir(k, sobre);
}

const guardado = {
  leer(k) { try { return JSON.parse(localStorage.getItem(k)); } catch { return null; } },
  poner(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} },
  quitar(k) { try { localStorage.removeItem(k); } catch {} },
};

// ---- registro compartido (ntfy.sh): solo viajan referencias ilegibles, nunca nombres
const NTFY = "https://ntfy.sh/";
async function refDe(codigo) {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode("ref:" + codigo)))).slice(0, 16);
}
async function enviar(evento) {
  const r = await fetch(NTFY + ZD.canal, { method: "POST", body: JSON.stringify(evento) });
  if (!r.ok) throw new Error("canal " + r.status);
  return r.json();
}
async function leerCanal() {
  const r = await fetch(NTFY + ZD.canal + "/json?poll=1&since=all", { cache: "no-store" });
  if (!r.ok) throw new Error("canal " + r.status);
  return (await r.text()).split("\n").filter(Boolean).map((l) => JSON.parse(l)).filter((m) => m.event === "message");
}

"use strict";
/*
 * app.ts - frontend for the password generator.
 * It reads the options from the UI, asks the Python backend to generate the
 * secret, and shows the result plus a live strength bar. All generation happens
 * on the backend; the frontend only collects options and displays the output.
 * The Vault tab saves generated passwords to an encrypted store on the backend.
 */
const $ = (id) => document.getElementById(id);
const output = $("output");
const strengthEl = $("strength");
const entropyEl = $("entropy");
const barFill = $("barFill");
let mode = "random";
const COLORS = {
    Weak: "var(--weak)", Medium: "var(--medium)", Strong: "var(--strong)",
};
function render(data) {
    if (data.error) {
        output.value = data.error;
        return;
    }
    output.value = data.password;
    strengthEl.textContent = data.strength;
    strengthEl.style.color = COLORS[data.strength];
    entropyEl.textContent = `Entropy: ${data.entropy} bits`;
    const pct = Math.min(100, (data.entropy / 128) * 100); // 128 bits = full bar
    barFill.style.width = pct + "%";
    barFill.style.background = COLORS[data.strength];
}
async function post(url, body) {
    const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
    });
    return res.json();
}
function checked(id) { return ($(id).checked); }
function num(id) { return parseInt($(id).value, 10); }
function val(id) { return $(id).value; }
async function generate() {
    if (mode === "random") {
        const data = await post("/api/generate", {
            length: num("length"),
            upper: checked("upper"),
            lower: checked("lower"),
            digits: checked("digits"),
            symbols: checked("symbols"),
            avoidAmbiguous: checked("avoidAmbiguous"),
        });
        render(data);
    }
    else if (mode === "phrase") {
        const data = await post("/api/passphrase", {
            words: num("words"),
            separator: val("separator") || "-",
            capitalize: checked("capitalize"),
            addNumber: checked("addNumber"),
        });
        render(data);
    }
    // vault mode never regenerates; it keeps whatever password is in the box.
}
// keep at least one character type selected in random mode
function guardTypes(changed) {
    const types = ["upper", "lower", "digits", "symbols"];
    if (!types.some(checked)) {
        $(changed).checked = true;
    }
}
// ----- Vault -----
function vaultMsg(text, kind) {
    const el = $("vmsg");
    el.textContent = text;
    el.className = kind;
}
function renderVault(entries) {
    const list = $("vlist");
    list.innerHTML = "";
    if (entries.length === 0) {
        list.innerHTML = `<p class="sub">No saved passwords yet.</p>`;
        return;
    }
    for (const e of entries) {
        const row = document.createElement("div");
        row.className = "vrow";
        const left = document.createElement("div");
        left.innerHTML = `<div class="vlabel"></div><div class="vpw"></div>`;
        left.querySelector(".vlabel").textContent = e.label;
        left.querySelector(".vpw").textContent = e.password;
        const date = document.createElement("div");
        date.className = "vdate";
        date.textContent = e.created;
        row.appendChild(left);
        row.appendChild(date);
        list.appendChild(row);
    }
}
async function vaultSave() {
    const master = val("master");
    const label = val("vlabel").trim();
    const password = output.value;
    if (!master) {
        vaultMsg("Enter a master password first.", "err");
        return;
    }
    if (!label) {
        vaultMsg("Give this password a label (e.g. Gmail).", "err");
        return;
    }
    if (!password) {
        vaultMsg("Generate a password first (Random or Passphrase tab).", "err");
        return;
    }
    const data = await post("/api/vault/save", { master, label, password });
    if (data.error) {
        vaultMsg(data.error, "err");
        return;
    }
    vaultMsg(`Saved "${label}" (encrypted). Vault now holds ${data.count}.`, "ok");
    $("vlabel").value = "";
}
async function vaultUnlock() {
    const master = val("master");
    if (!master) {
        vaultMsg("Enter your master password.", "err");
        return;
    }
    const data = await post("/api/vault/unlock", { master });
    if (data.error) {
        vaultMsg(data.error, "err");
        renderVault([]);
        return;
    }
    const entries = data.entries || [];
    vaultMsg(`Unlocked. ${entries.length} saved password(s) decrypted.`, "ok");
    renderVault(entries);
}
function wireUp() {
    ($("length")).addEventListener("input", () => {
        $("lengthVal").textContent = val("length");
        generate();
    });
    ($("words")).addEventListener("input", () => {
        $("wordsVal").textContent = val("words");
        generate();
    });
    ["upper", "lower", "digits", "symbols", "avoidAmbiguous"].forEach((id) => $(id).addEventListener("change", () => { guardTypes(id); generate(); }));
    ["capitalize", "addNumber"].forEach((id) => $(id).addEventListener("change", generate));
    $("separator").addEventListener("input", generate);
    $("regen").addEventListener("click", generate);
    $("copy").addEventListener("click", async () => {
        await navigator.clipboard.writeText(output.value);
        const b = $("copy");
        b.textContent = "Copied!";
        setTimeout(() => { b.textContent = "Copy"; }, 1200);
    });
    $("tabRandom").addEventListener("click", () => setMode("random"));
    $("tabPhrase").addEventListener("click", () => setMode("phrase"));
    $("tabVault").addEventListener("click", () => setMode("vault"));
    $("vsave").addEventListener("click", vaultSave);
    $("vunlock").addEventListener("click", vaultUnlock);
}
function setMode(m) {
    mode = m;
    $("tabRandom").classList.toggle("active", m === "random");
    $("tabPhrase").classList.toggle("active", m === "phrase");
    $("tabVault").classList.toggle("active", m === "vault");
    $("randomControls").classList.toggle("hidden", m !== "random");
    $("phraseControls").classList.toggle("hidden", m !== "phrase");
    $("vaultControls").classList.toggle("hidden", m !== "vault");
    if (m !== "vault") {
        generate();
    } // vault keeps the current password
}
wireUp();
generate();

/*
 * app.ts - Frontend logic tailored to the NordPass password generator UI.
 * Collects options from character/word controls, communicates with the backend API,
 * and updates output text, strength indicator, and clipboard actions.
 */

interface GenResult {
  password: string;
  entropy: number;
  strength: "Weak" | "Medium" | "Strong";
  poolSize?: number;
  wordlistSize?: number;
  error?: string;
}

const $ = (id: string): HTMLElement => document.getElementById(id)!;

// UI Element References
const output = $("output") as HTMLInputElement;
const strengthEl = $("strength");
const barFill = $("barFill");
const lengthVal = $("lengthVal");
const wordsVal = $("wordsVal");

let mode: "characters" | "words" = "characters";

const COLORS: Record<string, string> = {
  Weak: "#e05252",
  Medium: "#f5a623",
  Strong: "#2eaf67",
};

/**
 * Renders the generated password and security metrics in NordPass style.
 */
function render(data: GenResult): void {
  if (data.error) {
    output.value = data.error;
    return;
  }

  output.value = data.password;

  // Format strength badge matching NordPass ("✔ Strong Password")
  const strengthLabel = data.strength === "Strong" ? "Strong Password" : `${data.strength} Password`;
  strengthEl.innerHTML = `<span style="margin-right: 6px;">✔</span>${strengthLabel}`;
  strengthEl.style.color = COLORS[data.strength] || COLORS.Strong;

  if (barFill) {
    const pct = Math.min(100, (data.entropy / 128) * 100);
    barFill.style.width = `${pct}%`;
    barFill.style.background = COLORS[data.strength] || COLORS.Strong;
  }
}

/**
 * Sends request to python backend generator endpoints.
 */
async function post(url: string, body: object): Promise<GenResult> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return res.json();
}

function checked(id: string): boolean {
  const el = $(id) as HTMLInputElement | null;
  return el ? el.checked : false;
}

function num(id: string): number {
  const el = $(id) as HTMLInputElement | null;
  return el ? parseInt(el.value, 10) : 16;
}

/**
 * Triggers API call based on active mode ("Characters" vs "Words").
 */
async function generate(): Promise<void> {
  if (mode === "characters") {
    const data = await post("/api/generate", {
      length: num("length"),
      upper: checked("upper"),
      lower: checked("lower") || true, // Default to true if hidden in NordPass UI
      digits: checked("digits"),
      symbols: checked("symbols"),
      avoidAmbiguous: checked("avoidAmbiguous"),
    });
    render(data);
  } else {
    const data = await post("/api/passphrase", {
      words: num("words"),
      separator: ($("separator") as HTMLInputElement)?.value || "-",
      capitalize: checked("capitalize"),
      addNumber: checked("addNumber"),
    });
    render(data);
  }
}

/**
 * Ensures at least one character type remains active.
 */
function guardTypes(changed: string): void {
  const types = ["upper", "digits", "symbols"];
  if (checked("lower")) types.push("lower");
  
  if (!types.some(checked)) {
    const el = $(changed) as HTMLInputElement | null;
    if (el) el.checked = true;
  }
}

/**
 * Attaches event listeners matching NordPass controls layout.
 */
function wireUp(): void {
  // Mode selection via Radio Buttons ("Characters" / "Words")
  const typeCharEl = $("typeCharacters") as HTMLInputElement | null;
  const typeWordEl = $("typeWords") as HTMLInputElement | null;

  if (typeCharEl) {
    typeCharEl.addEventListener("change", () => {
      if (typeCharEl.checked) setMode("characters");
    });
  }
  if (typeWordEl) {
    typeWordEl.addEventListener("change", () => {
      if (typeWordEl.checked) setMode("words");
    });
  }

  // Length & Word count Sliders
  const lengthSlider = $("length") as HTMLInputElement | null;
  if (lengthSlider) {
    lengthSlider.addEventListener("input", () => {
      if (lengthVal) lengthVal.textContent = lengthSlider.value;
      generate();
    });
  }

  const wordsSlider = $("words") as HTMLInputElement | null;
  if (wordsSlider) {
    wordsSlider.addEventListener("input", () => {
      if (wordsVal) wordsVal.textContent = wordsSlider.value;
      generate();
    });
  }

  // Character Type Toggles
  ["upper", "digits", "symbols", "avoidAmbiguous"].forEach((id) => {
    const el = $(id);
    if (el) {
      el.addEventListener("change", () => {
        guardTypes(id);
        generate();
      });
    }
  });

  // Passphrase Toggles
  ["capitalize", "addNumber"].forEach((id) => {
    const el = $(id);
    if (el) el.addEventListener("change", generate);
  });

  const sepEl = $("separator");
  if (sepEl) sepEl.addEventListener("input", generate);

  // Quick Action Buttons (Regenerate, Copy, Save)
  const regenBtn = $("regen");
  if (regenBtn) regenBtn.addEventListener("click", generate);

  const copyBtn = $("copy");
  if (copyBtn) {
    copyBtn.addEventListener("click", async () => {
      await navigator.clipboard.writeText(output.value);
      const originalTitle = copyBtn.getAttribute("title") || "";
      copyBtn.setAttribute("title", "Copied!");
      copyBtn.classList.add("copied");
      setTimeout(() => {
        copyBtn.setAttribute("title", originalTitle);
        copyBtn.classList.remove("copied");
      }, 1500);
    });
  }
}

/**
 * Switches UI view between Character and Word generation modes.
 */
function setMode(m: "characters" | "words"): void {
  mode = m;

  const charControls = $("characterControls");
  const wordControls = $("wordsControls");

  if (charControls) charControls.classList.toggle("hidden", m !== "characters");
  if (wordControls) wordControls.classList.toggle("hidden", m !== "words");

  generate();
}

// Initialize application
wireUp();
generate();
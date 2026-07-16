// Password Strength API — techtenstein
const SPEC = {
  openapi: "3.1.0",
  info: {
    title: "Password Strength API",
    version: "1.0.0",
    description: "Scores password strength (0-4), estimates crack time, flags common patterns and dictionary matches, and generates strong passwords. Zero-key, CORS-enabled. Passwords are never logged.",
    contact: { name: "Techtenstein", url: "https://techtenstein.com", email: "sathvickollu@gmail.com" },
    license: { name: "MIT", url: "https://opensource.org/licenses/MIT" }
  },
  servers: [{ url: "https://password-strength.techtenstein.com" }],
  paths: {
    "/check": {
      get: {
        summary: "Score a password",
        parameters: [{ name: "password", in: "query", required: true, schema: { type: "string" } }],
        responses: { "200": { description: "Score + feedback" } }
      }
    },
    "/generate": {
      get: {
        summary: "Generate a strong password",
        parameters: [
          { name: "length", in: "query", schema: { type: "integer", default: 20, minimum: 8, maximum: 128 } },
          { name: "symbols", in: "query", schema: { type: "boolean", default: true } },
          { name: "numbers", in: "query", schema: { type: "boolean", default: true } },
          { name: "count", in: "query", schema: { type: "integer", default: 1, minimum: 1, maximum: 20 } }
        ],
        responses: { "200": { description: "Passwords" } }
      }
    },
    "/passphrase": {
      get: {
        summary: "Generate a passphrase (diceware-style)",
        parameters: [
          { name: "words", in: "query", schema: { type: "integer", default: 5, minimum: 3, maximum: 12 } },
          { name: "separator", in: "query", schema: { type: "string", default: "-" } }
        ],
        responses: { "200": { description: "Passphrase" } }
      }
    },
    "/health": { get: { summary: "Health", responses: { "200": { description: "OK" } } } }
  }
};

const COMMON = new Set([
  "password","123456","12345678","qwerty","abc123","monkey","letmein","dragon","111111","baseball",
  "iloveyou","trustno1","1234567","sunshine","master","welcome","shadow","ashley","football","jesus",
  "michael","ninja","mustang","password1","admin","login","hello","freedom","whatever","qazwsx",
  "starwars","superman","batman","password123","1234","12345","000000","1q2w3e4r","qwerty123","zaq12wsx",
  "letmein123","admin123","root","toor","pass","test","guest","user","default","changeme","secret",
  "iloveu","princess","charlie","donald","qwertyuiop","696969","killer","hunter","robert","matthew"
]);
const WORDLIST = "apple bright cloud dance eagle flame grape happy island jazz king lemon moon night ocean pearl quiet rain sunny tiger umbrella violet wave yellow zebra bear cat dog elk fox goat horse iguana jaguar koala lion mouse newt owl panda quail rat snake toad urchin viper whale yak zebu amber bronze coral daisy ember forest garnet hazel indigo jade kite luna maple nova opal plum quartz ruby silver topaz umber vine willow xenon yolk zephyr storm river valley canyon desert forest glacier harbor island jungle lagoon meadow desert plateau prairie reef savanna tundra wetland arctic boreal citrus dune".split(/\s+/);

function analyze(pw) {
  const len = pw.length;
  let classes = 0;
  const has = {
    lower: /[a-z]/.test(pw),
    upper: /[A-Z]/.test(pw),
    digit: /[0-9]/.test(pw),
    symbol: /[^A-Za-z0-9]/.test(pw)
  };
  classes = Object.values(has).filter(Boolean).length;
  const pool = (has.lower?26:0) + (has.upper?26:0) + (has.digit?10:0) + (has.symbol?33:0);
  const entropy = len && pool ? Math.round(len * Math.log2(pool) * 100) / 100 : 0;
  const lower = pw.toLowerCase();
  const feedback = [];
  let penalty = 0;
  if (COMMON.has(lower)) { penalty += 40; feedback.push("Very common password — pick something unique."); }
  if (/^\d+$/.test(pw)) { penalty += 15; feedback.push("Digits only — add letters and symbols."); }
  if (/(.)\1{2,}/.test(pw)) { penalty += 8; feedback.push("Avoid runs of the same character."); }
  if (/(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|qwer|asdf)/i.test(pw)) { penalty += 10; feedback.push("Avoid sequential characters like 1234 or qwer."); }
  if (len < 8) { penalty += 25; feedback.push("Too short — use at least 12 characters."); }
  else if (len < 12) { penalty += 10; feedback.push("Consider 12+ characters."); }
  if (classes < 3) feedback.push("Mix upper, lower, digits, and symbols.");
  let score;
  const adjusted = entropy - penalty;
  if (adjusted < 28) score = 0;
  else if (adjusted < 40) score = 1;
  else if (adjusted < 55) score = 2;
  else if (adjusted < 75) score = 3;
  else score = 4;
  // 10^10 guesses/sec offline attacker
  const guesses = Math.pow(2, Math.max(0, entropy - penalty));
  const seconds = guesses / 1e10;
  return {
    score,
    strength: ["very weak","weak","fair","strong","very strong"][score],
    length: len,
    entropy_bits: entropy,
    adjusted_entropy_bits: Math.max(0, Math.round(adjusted*100)/100),
    character_pool: pool,
    classes,
    has,
    crack_time_seconds: seconds,
    crack_time_display: humanTime(seconds),
    common: COMMON.has(lower),
    feedback: feedback.length ? feedback : ["Looks strong."]
  };
}
function humanTime(s) {
  if (s < 1) return "instant";
  if (s < 60) return `${Math.round(s)} seconds`;
  if (s < 3600) return `${Math.round(s/60)} minutes`;
  if (s < 86400) return `${Math.round(s/3600)} hours`;
  if (s < 31536000) return `${Math.round(s/86400)} days`;
  const y = s/31536000;
  if (y < 1000) return `${Math.round(y)} years`;
  if (y < 1e6) return `${Math.round(y/1000)}k years`;
  if (y < 1e9) return `${Math.round(y/1e6)}M years`;
  if (y < 1e12) return `${Math.round(y/1e9)}B years`;
  return "centuries";
}
function generate(len, symbols, numbers) {
  let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if (numbers) chars += "0123456789";
  if (symbols) chars += "!@#$%^&*()-_=+[]{}<>?,.:;";
  const arr = new Uint32Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr, v => chars[v % chars.length]).join("");
}
function passphrase(n, sep) {
  const arr = new Uint32Array(n);
  crypto.getRandomValues(arr);
  return Array.from(arr, v => WORDLIST[v % WORDLIST.length]).join(sep);
}

function json(o, status=200) {
  return new Response(JSON.stringify(o, null, 2), { status, headers: {
    "Content-Type":"application/json",
    "Access-Control-Allow-Origin":"*",
    "Cache-Control":"no-store"
  }});
}
const HOME = `<!doctype html><html><head><meta charset=utf-8><title>Password Strength API</title>
<style>body{font:16px/1.5 -apple-system,sans-serif;max-width:780px;margin:2rem auto;padding:0 1rem;color:#111}code{background:#f4f4f4;padding:2px 6px;border-radius:4px}pre{background:#f4f4f4;padding:1rem;border-radius:8px;overflow-x:auto}h1{border-bottom:2px solid #111;padding-bottom:.3em}a{color:#0366d6}.priv{background:#fff4e6;padding:1rem;border-radius:8px;border-left:4px solid #ff9500}</style></head><body>
<h1>🔐 Password Strength API</h1>
<p>Score passwords (0-4), estimate crack time, and generate strong passwords or passphrases. Free, no key, CORS-enabled.</p>
<div class=priv><b>Privacy:</b> passwords are processed in-memory at the edge and never logged.</div>
<h2>Endpoints</h2>
<ul>
<li><code>GET /check?password=hunter2</code></li>
<li><code>GET /generate?length=24&symbols=true&count=3</code></li>
<li><code>GET /passphrase?words=5</code></li>
<li><code>GET /openapi.json</code> · <code>GET /health</code></li>
</ul>
<pre>curl "https://password-strength.techtenstein.com/check?password=CorrectHorseBatteryStaple"</pre>
<p><a href="/openapi.json">OpenAPI spec</a> · MIT · <a href="https://techtenstein.com">techtenstein.com</a></p>
</body></html>`;

export default {
  async fetch(req) {
    const url = new URL(req.url);
    const p = url.pathname;
    if (req.method === "OPTIONS") return new Response(null, { headers: { "Access-Control-Allow-Origin":"*", "Access-Control-Allow-Methods":"GET, OPTIONS" }});
    if (p === "/" || p === "") return new Response(HOME, { headers: { "Content-Type":"text/html; charset=utf-8", "Access-Control-Allow-Origin":"*" }});
    if (p === "/health") return json({ status:"ok", service:"password-strength", version:"1.0.0" });
    if (p === "/openapi.json") return json(SPEC);
    if (p === "/check") {
      const pw = url.searchParams.get("password");
      if (pw === null) return json({ error:"password parameter required" }, 400);
      return json(analyze(pw));
    }
    if (p === "/generate") {
      const length = Math.max(8, Math.min(128, parseInt(url.searchParams.get("length")||"20")));
      const symbols = (url.searchParams.get("symbols")||"true") !== "false";
      const numbers = (url.searchParams.get("numbers")||"true") !== "false";
      const count = Math.max(1, Math.min(20, parseInt(url.searchParams.get("count")||"1")));
      const passwords = Array.from({length: count}, () => generate(length, symbols, numbers));
      return json({ count, length, passwords, sample_score: analyze(passwords[0]) });
    }
    if (p === "/passphrase") {
      const words = Math.max(3, Math.min(12, parseInt(url.searchParams.get("words")||"5")));
      const separator = url.searchParams.get("separator") || "-";
      const pp = passphrase(words, separator);
      return json({ passphrase: pp, words, separator, score: analyze(pp) });
    }
    return json({ error:"not found", endpoints:["/check","/generate","/passphrase","/openapi.json","/health"] }, 404);
  }
};

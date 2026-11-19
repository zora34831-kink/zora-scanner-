
const https = require("https");
const dns = require("dns").promises;
const net = require("net");

function isPublic(ip) {
  if (net.isIP(ip) !== 4) return false;

  const [a, b] = ip.split(".").map(Number);

  return !(
    a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 192 && b === 0) ||
    (a === 198 && (b === 18 || b === 19))
  );
}

async function validate(target) {
  const url = new URL(target);

  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.port ||
    net.isIP(url.hostname) ||
    !url.hostname.includes(".")
  ) {
    throw new Error("Invalid public HTTPS URL.");
  }

  const addresses = await dns.lookup(url.hostname, {
    all: true,
    verbatim: true
  });

  if (
    !addresses.length ||
    addresses.some(x => !isPublic(x.address))
  ) {
    throw new Error("Non-public IP address blocked.");
  }

  return url;
}

function request(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      timeout: 10000,
      maxHeaderSize: 16384,
      headers: {
        "User-Agent": "ZORA-Security-Scanner/1.0",
        "Accept": "text/html"
      }
    }, response => {
      let size = 0;

      response.on("data", chunk => {
        size += chunk.length;

        if (size > 65536) {
          req.destroy(new Error("Response too large."));
        }
      });

      response.on("end", () => {
        resolve({
          status: response.statusCode,
          headers: response.headers
        });
      });
    });

    req.on("timeout", () => {
      req.destroy(new Error("Request timeout."));
    });

    req.on("error", reject);
  });
}

async function scan(target, depth = 0) {
  const url = await validate(target);
  const result = await request(url);

  if (
    [301, 302, 303, 307, 308].includes(result.status) &&
    result.headers.location
  ) {
    if (depth >= 4) {
      throw new Error("Too many redirects.");
    }

    return scan(
      new URL(result.headers.location, url).href,
      depth + 1
    );
  }

  return {
    target: url.origin,
    status: result.status,
    headers: result.headers
  };
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      error: "Method not allowed."
    });
  }

  try {
    const target = req.body?.url;

    if (typeof target !== "string" || target.length > 2048) {
      throw new Error("Invalid URL.");
    }

    const result = await scan(target);
    const h = result.headers;

    const checks = [
      ["HTTPS Connection", true],
      ["Content Security Policy", !!h["content-security-policy"]],
      ["Strict Transport Security", !!h["strict-transport-security"]],
      [
        "X-Frame-Options",
        !!h["x-frame-options"] ||
        /frame-ancestors/i.test(h["content-security-policy"] || "")
      ],
      [
        "X-Content-Type-Options",
        /nosniff/i.test(h["x-content-type-options"] || "")
      ],
      ["Referrer Policy", !!h["referrer-policy"]],
      ["Permissions Policy", !!h["permissions-policy"]]
    ].map(([name, pass]) => ({
      name,
      pass,
      detail: pass ? "Protection detected." : "Header missing."
    }));

    const cookies = (h["set-cookie"] || []).map(cookie => ({
      name: cookie.split(";")[0].split("=")[0],
      secure: /;\s*secure/i.test(cookie),
      httpOnly: /;\s*httponly/i.test(cookie),
      sameSite: /;\s*samesite=/i.test(cookie)
    }));

    const passed = checks.filter(c => c.pass).length;

    const issues = cookies.reduce((sum, c) =>
      sum + (!c.secure ? 1 : 0) +
      (!c.httpOnly ? 1 : 0) +
      (!c.sameSite ? 1 : 0), 0
    );

    const score = Math.max(
      0,
      Math.round(
        passed / checks.length * 100 -
        Math.min(issues * 3, 15)
      )
    );

    return res.status(200).json({
      success: true,
      target: result.target,
      status: result.status,
      score,
      checks,
      cookies,
      scannedAt: new Date().toISOString(),
      disclaimer: "Passive configuration analysis only."
    });

  } catch (error) {
    console.error("ZORA SCANNER ERROR:", error);

    return res.status(400).json({
      success: false,
      error: error.message || "Scan failed."
    });
  }
};

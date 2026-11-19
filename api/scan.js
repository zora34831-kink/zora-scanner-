
const https = require("https");
const dns = require("dns").promises;
const net = require("net");

function isPublicIPv4(ip) {
  if (net.isIP(ip) !== 4) return false;
  const p = ip.split(".").map(Number);

  return !(
    p[0] === 0 ||
    p[0] === 10 ||
    p[0] === 127 ||
    p[0] >= 224 ||
    (p[0] === 169 && p[1] === 254) ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    (p[0] === 100 && p[1] >= 64 && p[1] <= 127)
  );
}

async function validate(url) {
  const u = new URL(url);

  if (u.protocol !== "https:") {
    throw new Error("Only HTTPS websites are supported.");
  }

  if (u.username || u.password || u.port && u.port !== "443") {
    throw new Error("Invalid URL or port.");
  }

  if (net.isIP(u.hostname)) {
    throw new Error("IP addresses are not accepted.");
  }

  const records = await dns.lookup(u.hostname, { all: true });

  if (!records.length || records.some(x => !isPublicIPv4(x.address))) {
    throw new Error("Website address is not allowed.");
  }

  const ipv4 = records.find(x => x.family === 4);

  if (!ipv4) throw new Error("Public IPv4 address required.");

  return { url: u, ip: ipv4.address };
}

function requestPage(url, ip) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: url.hostname,
      servername: url.hostname,
      port: 443,
      path: url.pathname + url.search,
      method: "GET",
      lookup: (host, options, callback) =>
        callback(null, ip, 4),
      headers: {
        "User-Agent": "ZORA-Security-Scanner/1.0",
        "Accept": "text/html,application/xhtml+xml"
      },
      timeout: 10000,
      maxHeaderSize: 16384
    }, res => {
      let size = 0;

      res.on("data", chunk => {
        size += chunk.length;
        if (size > 65536) req.destroy(
          new Error("Response too large")
        );
      });

      res.on("end", () => resolve({
        status: res.statusCode,
        headers: res.headers
      }));
    });

    req.on("timeout", () => req.destroy(
      new Error("Request timeout")
    ));

    req.on("error", reject);
    req.end();
  });
}

async function scan(target, redirects = 0) {
  const { url, ip } = await validate(target);
  const result = await requestPage(url, ip);

  const location = result.headers.location;

  if ([301, 302, 303, 307, 308].includes(result.status)
      && location) {
    if (redirects >= 4) {
      throw new Error("Too many redirects.");
    }

    const next = new URL(location, url).toString();
    return scan(next, redirects + 1);
  }

  return { url: url.origin, ...result };
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    return res.status(405).json({
      error: "Method not allowed"
    });
  }

  try {
    const target = req.body?.url;

    if (typeof target !== "string" || target.length > 2048) {
      return res.status(400).json({
        error: "Invalid URL."
      });
    }

    const data = await scan(target);
    const h = data.headers;

    const checks = [
      {
        name: "HTTPS Connection",
        pass: true,
        detail: "HTTPS connection established"
      },
      {
        name: "Content Security Policy",
        pass: !!h["content-security-policy"],
        detail: h["content-security-policy"]
          ? "CSP header detected"
          : "CSP header missing"
      },
      {
        name: "Strict Transport Security",
        pass: !!h["strict-transport-security"],
        detail: h["strict-transport-security"]
          ? "HSTS header detected"
          : "HSTS header missing"
      },
      {
        name: "X-Frame-Options",
        pass: !!h["x-frame-options"] ||
              /frame-ancestors/i.test(h["content-security-policy"] || ""),
        detail: "Frame protection header check"
      },
      {
        name: "X-Content-Type-Options",
        pass: /nosniff/i.test(h["x-content-type-options"] || ""),
        detail: "MIME sniffing protection check"
      },
      {
        name: "Referrer Policy",
        pass: !!h["referrer-policy"],
        detail: "Referrer policy check"
      },
      {
        name: "Permissions Policy",
        pass: !!h["permissions-policy"],
        detail: "Browser permissions policy check"
      }
    ];

    const cookies = h["set-cookie"] || [];
    const cookieChecks = cookies.map(cookie => ({
      name: cookie.split(";")[0].split("=")[0],
      secure: /;\s*secure/i.test(cookie),
      httpOnly: /;\s*httponly/i.test(cookie),
      sameSite: /;\s*samesite=/i.test(cookie)
    }));

    const cookieIssues = cookieChecks.reduce(
      (total, c) =>
        total + (!c.secure ? 1 : 0) +
        (!c.httpOnly ? 1 : 0) +
        (!c.sameSite ? 1 : 0), 0
    );

    const passed = checks.filter(c => c.pass).length;
    const score = Math.max(
      0,
      Math.round(
        (passed / checks.length) * 100 -
        Math.min(cookieIssues * 3, 15)
      )
    );

    return res.status(200).json({
      success: true,
      target: data.url,
      status: data.status,
      score,
      checks,
      cookies: cookieChecks,
      scannedAt: new Date().toISOString(),
      disclaimer: "Passive checks only. This is not a complete security audit."
    });

  } catch (error) {
    return res.status(400).json({
      success: false,
      error: error.message || "Scan failed."
    });
  }
}

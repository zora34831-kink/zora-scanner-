
const https = require("https");
const dns = require("dns").promises;
const net = require("net");

function isPublicIP(ip) {
  if (net.isIP(ip) !== 4) return false;

  const [a, b, c] = ip.split(".").map(Number);

  return !(
    a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113)
  );
}

async function validateURL(target) {
  let url;

  try {
    url = new URL(target);
  } catch {
    throw new Error("Invalid website URL.");
  }

  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    (url.port && url.port !== "443") ||
    net.isIP(url.hostname) ||
    !url.hostname.includes(".") ||
    url.hostname.endsWith(".local")
  ) {
    throw new Error("Only public HTTPS websites are allowed.");
  }

  const addresses = await dns.resolve4(url.hostname);

  if (!addresses.length || addresses.some(ip => !isPublicIP(ip))) {
    throw new Error("Website IP address is not allowed.");
  }

  return {
    url,
    ip: addresses[0]
  };
}

function requestWebsite(url, ip) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: url.hostname,
      servername: url.hostname,
      port: 443,
      path: url.pathname + url.search,
      method: "GET",
      family: 4,
      lookup: (hostname, options, callback) => {
        if (typeof options === "function") {
          callback = options;
          options = {};
        }

        if (typeof callback !== "function") {
          return;
        }

        if (!isPublicIP(ip)) {
          return callback(new Error("Invalid IP address."));
        }

        if (options && options.all) {
          callback(null, [{
            address: ip,
            family: 4
          }]);
        } else {
          callback(null, ip, 4);
        }
      },
      headers: {
        "User-Agent": "ZORA-Security-Scanner/1.0",
        "Accept": "text/html,application/xhtml+xml"
      },
      timeout: 10000,
      maxHeaderSize: 16384
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
    req.end();
  });
}

async function performScan(target, redirects = 0) {
  const { url, ip } = await validateURL(target);

  const result = await requestWebsite(url, ip);

  const redirectCodes = [301, 302, 303, 307, 308];

  if (
    redirectCodes.includes(result.status) &&
    result.headers.location
  ) {
    if (redirects >= 4) {
      throw new Error("Maximum redirects exceeded.");
    }

    const nextURL = new URL(
      result.headers.location,
      url
    ).toString();

    return performScan(nextURL, redirects + 1);
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

    if (
      typeof target !== "string" ||
      target.length > 2048
    ) {
      return res.status(400).json({
        success: false,
        error: "Invalid URL."
      });
    }

    const result = await performScan(target);
    const h = result.headers;

    const checks = [
      {
        name: "HTTPS Connection",
        pass: true,
        detail: "HTTPS connection established."
      },
      {
        name: "Content Security Policy",
        pass: !!h["content-security-policy"],
        detail: h["content-security-policy"]
          ? "CSP header detected."
          : "CSP header missing."
      },
      {
        name: "Strict Transport Security",
        pass: !!h["strict-transport-security"],
        detail: h["strict-transport-security"]
          ? "HSTS header detected."
          : "HSTS header missing."
      },
      {
        name: "X-Frame-Options",
        pass: !!h["x-frame-options"] ||
          /frame-ancestors/i.test(
            h["content-security-policy"] || ""
          ),
        detail: "Frame protection check."
      },
      {
        name: "X-Content-Type-Options",
        pass: /nosniff/i.test(
          h["x-content-type-options"] || ""
        ),
        detail: "MIME protection check."
      },
      {
        name: "Referrer Policy",
        pass: !!h["referrer-policy"],
        detail: "Referrer policy check."
      },
      {
        name: "Permissions Policy",
        pass: !!h["permissions-policy"],
        detail: "Permissions policy check."
      }
    ];

    const rawCookies = h["set-cookie"] || [];

    const cookies = rawCookies.map(cookie => ({
      name: cookie.split(";")[0].split("=")[0],
      secure: /;\s*secure/i.test(cookie),
      httpOnly: /;\s*httponly/i.test(cookie),
      sameSite: /;\s*samesite=/i.test(cookie)
    }));

    const passed = checks.filter(c => c.pass).length;

    const cookieIssues = cookies.reduce(
      (total, cookie) =>
        total +
        (!cookie.secure ? 1 : 0) +
        (!cookie.httpOnly ? 1 : 0) +
        (!cookie.sameSite ? 1 : 0),
      0
    );

    const score = Math.max(
      0,
      Math.round(
        (passed / checks.length) * 100 -
        Math.min(cookieIssues * 3, 15)
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
      disclaimer:
        "Passive security configuration analysis only."
    });

  } catch (error) {
    console.error("ZORA SCANNER ERROR:", error);

    return res.status(400).json({
      success: false,
      error: error.message || "Scanner failed."
    });
  }
};

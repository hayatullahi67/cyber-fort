// import express, { type Request, Response, NextFunction } from "express";
// import { registerRoutes } from "./routes";
// import { setupVite, serveStatic, log } from "./vite";

// const app = express();
// app.use(express.json());
// app.use(express.urlencoded({ extended: false }));

// app.use((req, res, next) => {
//   const start = Date.now();
//   const path = req.path;
//   let capturedJsonResponse: Record<string, any> | undefined = undefined;

//   const originalResJson = res.json;
//   res.json = function (bodyJson, ...args) {
//     capturedJsonResponse = bodyJson;
//     return originalResJson.apply(res, [bodyJson, ...args]);
//   };

//   res.on("finish", () => {
//     const duration = Date.now() - start;
//     if (path.startsWith("/api")) {
//       let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
//       if (capturedJsonResponse) {
//         logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
//       }

//       if (logLine.length > 80) {
//         logLine = logLine.slice(0, 79) + "…";
//       }

//       log(logLine);
//     }
//   });

//   next();
// });

// (async () => {
//   const server = await registerRoutes(app);

//   app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
//     const status = err.status || err.statusCode || 500;
//     const message = err.message || "Internal Server Error";

//     res.status(status).json({ message });
//     throw err;
//   });

//   // importantly only setup vite in development and after
//   // setting up all the other routes so the catch-all route
//   // doesn't interfere with the other routes
//   if (app.get("env") === "development") {
//     await setupVite(app, server);
//   } else {
//     serveStatic(app);
//   }

//   // ALWAYS serve the app on port 5000
//   // this serves both the API and the client.
//   // It is the only port that is not firewalled.
//   const port = 5000;
//   server.listen({
//     port,
//     host: "0.0.0.0",
//     reusePort: true,
//   }, () => {
//     log(`serving on port ${port}`);
//   });
// })();


import express, { type Request, Response, NextFunction } from "express";
import axios from 'axios';
import { registerRoutes } from "./routes";
import { setupVite, serveStatic, log } from "./vite";

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Environment variable for API key (set this in your Render dashboard)
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY || "fa445174a59c7519b96f92c1a1897ff5eb0d0a3051c0130ea7a039e63da29966";

// VirusTotal URL checking route
app.post('/api/check-url', async (req: Request, res: Response) => {
  try {
    const { url } = req.body;
    
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }
    
    // Preprocess and validate URL
    let processedUrl = url.trim();
    
    // Add http:// if no protocol is specified
    if (!processedUrl.startsWith('http://') && !processedUrl.startsWith('https://')) {
      processedUrl = `http://${processedUrl}`;
    }
    
    // Basic URL validation
    try {
      new URL(processedUrl);
    } catch (e) {
      return res.status(400).json({ error: "Invalid URL format. Please enter a valid URL." });
    }
    
    // First, submit the URL for analysis
    const scanResponse = await axios.post(
      'https://www.virustotal.com/api/v3/urls',
      new URLSearchParams({ url: processedUrl }),
      {
        headers: {
          'accept': 'application/json',
          'content-type': 'application/x-www-form-urlencoded',
          'x-apikey': VIRUSTOTAL_API_KEY
        }
      }
    );
    
    // Extract the analysis ID from the response
    const analysisId = scanResponse.data.data.id;
    
    // Get the analysis report
    const reportResponse = await axios.get(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        headers: {
          'accept': 'application/json',
          'x-apikey': VIRUSTOTAL_API_KEY
        }
      }
    );
    
    // Process the report results
    const report = reportResponse.data.data.attributes;
    const stats = report.stats;
    
    // Calculate risk score based on VirusTotal stats
    let riskScore = 0;
    let issues = [];
    
    // Add points based on malicious and suspicious verdicts
    if (stats.malicious > 0) {
      riskScore += (stats.malicious / stats.total) * 100;
      issues.push(`${stats.malicious} security vendors flagged this as malicious`);
    }
    if (stats.suspicious > 0) {
      riskScore += (stats.suspicious / stats.total) * 50;
      issues.push(`${stats.suspicious} security vendors flagged this as suspicious`);
    }
    
    // Check SSL/TLS
    let sslIssues = [];
    if (report.ssl_info) {
      if (!report.ssl_info.is_valid) {
        sslIssues.push("Invalid SSL certificate");
      }
      if (report.ssl_info.is_expired) {
        sslIssues.push("SSL certificate is expired");
      }
      if (report.ssl_info.is_self_signed) {
        sslIssues.push("SSL certificate is self-signed");
      }
    }
    
    // Determine if safe
    const isSafe = riskScore < 50;
    
    // Format response
    const result = {
      url: processedUrl,
      isSafe,
      result: issues.length > 0 ? issues.join(", ") : "No threats detected",
      sslIssues: sslIssues.length > 0 ? sslIssues : undefined,
      hasSslIssues: sslIssues.length > 0,
      riskScore: Math.min(riskScore, 100),
      stats: {
        total: stats.total,
        malicious: stats.malicious,
        suspicious: stats.suspicious,
        undetected: stats.undetected
      }
    };
    
    res.json(result);
  } catch (error: any) {
    console.error('Error checking URL:', error);
    
    if (error.response?.status === 401) {
      return res.status(401).json({ error: "Invalid VirusTotal API key. Please check your API key configuration." });
    } else if (error.response?.status === 429) {
      return res.status(429).json({ error: "Rate limit exceeded. Please try again in a few minutes." });
    } else {
      return res.status(500).json({ error: `Error checking URL: ${error.message}` });
    }
  }
});

// Logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;
  
  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "…";
      }
      log(logLine);
    }
  });
  next();
});

(async () => {
  const server = await registerRoutes(app);
  
  // Error handling middleware
  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    res.status(status).json({ message });
    throw err;
  });
  
  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  
  // ALWAYS serve the app on port 5000
  // this serves both the API and the client.
  // It is the only port that is not firewalled.
  const port = 5000;
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true,
  }, () => {
    log(`serving on port ${port}`);
  });
})();
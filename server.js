const express = require("express");
const WebSocket = require("ws");
const { v4: uuidv4 } = require("uuid");
const winston = require("winston");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const { z } = require("zod");
const Redis = require("ioredis");

dotenv.config();

const JWT_SECRET =
  process.env.JWT_SECRET || crypto.randomBytes(64).toString("hex");
const REDIS_URL = process.env.REDIS_URL || "redis://localhost:6379";
const redis = new Redis(REDIS_URL);

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
    winston.format.errors({ stack: true })
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    }),
    new winston.transports.File({
      filename: "error.log",
      level: "error",
      maxsize: 5242880,
      maxFiles: 5,
    }),
    new winston.transports.File({
      filename: "combined.log",
      maxsize: 5242880,
      maxFiles: 5,
    }),
  ],
});

const PORT = process.env.PORT || 8080;
const MAX_CONNECTIONS = process.env.MAX_CONNECTIONS || 1000;
const MAX_CONNECTIONS_PER_IP = process.env.MAX_CONNECTIONS_PER_IP || 5;
const MAX_MESSAGE_SIZE = process.env.MAX_MESSAGE_SIZE || 1024;
const HEARTBEAT_INTERVAL = process.env.HEARTBEAT_INTERVAL || 30000;
const CLEANUP_INTERVAL = process.env.CLEANUP_INTERVAL || 60000;
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",")
  : ["https://5years-production.up.railway.app"];

const messageSchema = z.object({
  type: z.enum([
    "init",
    "reconnect",
    "position",
    "emotion",
    "heartbeat",
    "disconnect",
  ]),
  sessionId: z.string().optional(),
  x: z.number().min(0).max(5000).optional(),
  emoji: z.string().max(4).optional(),
  timestamp: z.number(),
});

const positionSchema = z.object({
  x: z.number().min(0).max(5000),
});

const app = express();
const server = require("http").createServer(app);
const path = require("path");

app.use(express.json({ limit: "10kb" }));
app.use(
  express.static(path.join(__dirname, "public"), {
    maxAge: "1d",
    setHeaders: (res, path) => {
      res.setHeader("X-Content-Type-Options", "nosniff");
      res.setHeader("Cache-Control", "public, max-age=86400");
    },
  })
);

const corsMiddleware = (req, res, next) => {
  const origin = req.headers.origin;
  if (validateOrigin(origin)) {
    res.header("Access-Control-Allow-Origin", origin);
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.header(
      "Access-Control-Allow-Headers",
      "Origin, X-Requested-With, Content-Type, Accept, Authorization"
    );
    res.header("Access-Control-Max-Age", "86400");
  }
  next();
};

app.use(corsMiddleware);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        connectSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "blob:"],
        workerSrc: ["'self'", "blob:"],
        frameAncestors: ["'none'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    crossOriginEmbedderPolicy: { policy: "require-corp" },
    crossOriginResourcePolicy: { policy: "same-site" },
    crossOriginOpenerPolicy: { policy: "same-origin" },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
  })
);

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
    res.status(429).send("Too many requests");
  },
});

app.use(limiter);

const clients = new Map();
const ipConnections = new Map();

function validateOrigin(origin) {
  return (
    ALLOWED_ORIGINS.includes(origin) ||
    (process.env.NODE_ENV === "development" &&
      origin?.startsWith("http://localhost"))
  );
}

function rateLimit(ip) {
  const key = `ratelimit:${ip}`;
  return redis.incr(key).then((count) => {
    if (count === 1) {
      redis.expire(key, 60);
    }
    return count <= 30;
  });
}

async function validateSession(sessionId) {
  if (!sessionId) return false;
  const exists = await redis.exists(`session:${sessionId}`);
  return exists === 1;
}

const wss = new WebSocket.Server({
  server,
  verifyClient: async ({ req }, cb) => {
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    const origin = req.headers.origin;

    if (!validateOrigin(origin)) {
      logger.warn(
        `Invalid origin connection attempt: ${origin} from IP: ${ip}`
      );
      cb(false, 403, "Forbidden");
      return;
    }

    const connectionCount = ipConnections.get(ip) || 0;
    if (connectionCount >= MAX_CONNECTIONS_PER_IP) {
      logger.warn(`Max connections per IP reached: ${ip}`);
      cb(false, 429, "Too Many Connections");
      return;
    }

    const allowed = await rateLimit(ip);
    if (!allowed) {
      logger.warn(`Rate limit exceeded for IP: ${ip}`);
      cb(false, 429, "Too Many Requests");
      return;
    }

    cb(true);
  },
});

wss.on("connection", async (ws, req) => {
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  ipConnections.set(ip, (ipConnections.get(ip) || 0) + 1);

  let clientId = null;
  let messageCount = 0;
  let lastMessageTime = Date.now();

  const cleanup = () => {
    if (clientId) {
      clients.delete(clientId);
      const count = ipConnections.get(ip) - 1;
      if (count <= 0) {
        ipConnections.delete(ip);
      } else {
        ipConnections.set(ip, count);
      }
      broadcastViewerCount();
      redis.del(`session:${clientId}`);
    }
  };

  const messageRateCheck = () => {
    const now = Date.now();
    if (now - lastMessageTime < 1000) {
      messageCount++;
      if (messageCount > 10) {
        logger.warn(`Message rate limit exceeded for client ${clientId}`);
        ws.terminate();
        return false;
      }
    } else {
      messageCount = 0;
      lastMessageTime = now;
    }
    return true;
  };

  ws.on("message", async (message) => {
    try {
      if (!messageRateCheck()) return;
      if (message.length > MAX_MESSAGE_SIZE) {
        ws.terminate();
        return;
      }

      const data = messageSchema.parse(JSON.parse(message));

      switch (data.type) {
        case "init":
          clientId = crypto.randomBytes(32).toString("hex");
          await redis.setex(`session:${clientId}`, 86400, "active");
          clients.set(clientId, {
            ws,
            lastSeen: Date.now(),
            ip,
            x: Math.random() * 500,
          });
          ws.send(
            JSON.stringify({
              type: "init",
              sessionId: clientId,
            })
          );

          const avatars = Array.from(clients.entries()).map(([id, client]) => ({
            id,
            x: client.x || 0,
          }));
          ws.send(JSON.stringify({ type: "sync", avatars }));
          broadcastViewerCount();
          break;

        case "reconnect":
          if (await validateSession(data.sessionId)) {
            clientId = data.sessionId;
            const oldClient = clients.get(clientId);
            if (oldClient) {
              clients.set(clientId, {
                ws,
                lastSeen: Date.now(),
                ip,
                x: oldClient.x,
              });
              broadcastViewerCount();
            }
          }
          break;

        case "position":
          if (clientId && clients.has(clientId)) {
            const position = positionSchema.parse({ x: data.x });
            clients.get(clientId).x = position.x;
            broadcastToOthers(
              JSON.stringify({
                type: "position",
                sessionId: clientId,
                x: position.x,
              }),
              clientId
            );
          }
          break;

        case "emotion":
          if (clientId && clients.has(clientId)) {
            broadcastToOthers(
              JSON.stringify({
                type: "emotion",
                sessionId: clientId,
                emoji: data.emoji,
              }),
              clientId
            );
          }
          break;

        case "heartbeat":
          if (clientId && clients.has(clientId)) {
            clients.get(clientId).lastSeen = Date.now();
          }
          break;

        case "disconnect":
          cleanup();
          break;
      }
    } catch (error) {
      logger.error("Message processing error:", {
        error: error.message,
        clientId,
        type: "websocket_message_error",
      });
      ws.terminate();
    }
  });

  ws.on("close", cleanup);
  ws.on("error", (error) => {
    logger.error("WebSocket error:", {
      error: error.message,
      clientId,
      type: "websocket_error",
    });
    cleanup();
  });
});

setInterval(() => {
  const now = Date.now();
  clients.forEach((client, id) => {
    if (now - client.lastSeen > CLEANUP_INTERVAL) {
      clients.delete(id);
      broadcastToOthers(
        JSON.stringify({
          type: "disconnect",
          sessionId: id,
        }),
        id
      );
      broadcastViewerCount();
      redis.del(`session:${id}`);
    }
  });
}, HEARTBEAT_INTERVAL);

function broadcastToOthers(message, excludeId) {
  clients.forEach((client, id) => {
    if (id !== excludeId && client.ws.readyState === WebSocket.OPEN) {
      client.ws.send(message);
    }
  });
}

function broadcastViewerCount() {
  const count = clients.size;
  const message = JSON.stringify({
    type: "viewers",
    count,
  });

  clients.forEach((client) => {
    if (client.ws.readyState === WebSocket.OPEN) {
      client.ws.send(message);
    }
  });
}

function gracefulShutdown() {
  logger.info("Initiating graceful shutdown...");
  server.close(() => {
    logger.info("HTTP server closed");
    wss.clients.forEach((client) => {
      client.terminate();
    });
    redis.quit().then(() => {
      logger.info("Redis connection closed");
      process.exit(0);
    });
  });
}

process.on("SIGTERM", gracefulShutdown);
process.on("SIGINT", gracefulShutdown);

process.on("uncaughtException", (err) => {
  logger.error("Uncaught Exception:", err);
  gracefulShutdown();
});

process.on("unhandledRejection", (reason, promise) => {
  logger.error("Unhandled Rejection:", {
    reason,
    promise,
    type: "unhandled_rejection",
  });
});

server.listen(PORT, "0.0.0.0", () => {
  logger.info(`Server running on port ${PORT}`);
});

const express = require("express");
const WebSocket = require("ws");
const { v4: uuidv4 } = require("uuid");
const winston = require("winston");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const path = require("path");

const MAX_CONNECTIONS_PER_IP = 3;
const MIN_MESSAGE_INTERVAL = 100;
const MAX_CONNECTION_TIME = 4 * 60 * 60 * 1000;
const SAFE_EMOJIS = ["😊", "🎉", "❤️", "✨", "🤖"];

const ipConnections = new Map();
const messageTimestamps = new Map();

const logger = winston.createLogger({
  level: "info",
  format: winston.format.json(),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: "error.log", level: "error" }),
    new winston.transports.File({ filename: "combined.log" }),
  ],
});

const PORT = process.env.PORT || 8080;
const MAX_CONNECTIONS = 10000;
const MAX_MESSAGE_SIZE = 1024;
const HEARTBEAT_INTERVAL = 30000;
const CLEANUP_INTERVAL = 30000;
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",")
  : ["https://5years-production.up.railway.app"];

const app = express();
const server = require("http").createServer(app);

app.use(express.json({ limit: "10kb" }));
app.use(express.static(path.join(__dirname, "public")));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP",
});

app.use(limiter);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        connectSrc: ["'self'", "wss:", "ws:"],
        imgSrc: ["'self'", "data:", "blob:"],
        workerSrc: ["'self'", "blob:"],
      },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "same-site" },
  })
);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (validateOrigin(origin)) {
    res.header("Access-Control-Allow-Origin", origin);
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.header(
      "Access-Control-Allow-Headers",
      "Origin, X-Requested-With, Content-Type, Accept"
    );
  }
  next();
});

app.get("/health", (req, res) => {
  res.status(200).send("OK");
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const wss = new WebSocket.Server({
  server,
  verifyClient: ({ origin, req }, callback) => {
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    const currentConnections = ipConnections.get(ip) || 0;
    if (currentConnections >= MAX_CONNECTIONS_PER_IP) {
      callback(false, 429, "Too many connections");
      return;
    }
    callback(true);
  },
});

const clients = new Map();

function generateSessionId() {
  return crypto.randomBytes(32).toString("hex");
}

function validateMessage(message) {
  if (!message || message.length > MAX_MESSAGE_SIZE) return false;
  try {
    const data = JSON.parse(message);
    return !!data.type;
  } catch {
    return false;
  }
}

function validateEmoji(emoji) {
  return SAFE_EMOJIS.includes(emoji);
}

function validateOrigin(origin) {
  return (
    process.env.NODE_ENV === "development" || ALLOWED_ORIGINS.includes(origin)
  );
}

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
    count: count,
  });

  clients.forEach((client) => {
    if (client.ws.readyState === WebSocket.OPEN) {
      client.ws.send(message);
    }
  });
}

wss.on("connection", (ws, req) => {
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  ipConnections.set(ip, (ipConnections.get(ip) || 0) + 1);

  let clientId = null;
  const connectionTime = Date.now();

  if (!validateOrigin(req.headers.origin)) {
    ws.terminate();
    logger.warn(
      `Rejected connection from unauthorized origin: ${req.headers.origin}`
    );
    return;
  }

  if (clients.size >= MAX_CONNECTIONS) {
    ws.close(1013, "Maximum connections reached");
    logger.warn("Connection rejected: maximum connections reached");
    return;
  }

  ws.on("message", (message) => {
    try {
      const now = Date.now();
      const lastMessage = messageTimestamps.get(clientId) || 0;
      if (now - lastMessage < MIN_MESSAGE_INTERVAL) return;
      messageTimestamps.set(clientId, now);

      if (!validateMessage(message)) {
        ws.terminate();
        return;
      }

      const data = JSON.parse(message);
      logger.info(`Received message: ${data.type} from: ${clientId}`);

      switch (data.type) {
        case "init":
          clientId = generateSessionId();
          clients.set(clientId, {
            ws,
            lastSeen: now,
            connectTime: connectionTime,
            ip: ip,
            x: data.x || Math.random() * 500,
          });
          ws.send(JSON.stringify({ type: "init", sessionId: clientId }));

          const avatars = Array.from(clients.entries()).map(([id, client]) => ({
            id,
            x: client.x || 0,
          }));
          ws.send(JSON.stringify({ type: "sync", avatars }));

          broadcastToOthers(
            JSON.stringify({
              type: "position",
              sessionId: clientId,
              x: clients.get(clientId).x,
            }),
            clientId
          );
          broadcastViewerCount();
          break;

        case "reconnect":
          if (clients.has(data.sessionId)) {
            clientId = data.sessionId;
            const oldX = clients.get(clientId).x;
            clients.set(clientId, {
              ws,
              lastSeen: now,
              ip: ip,
              x: oldX,
            });
            broadcastViewerCount();
          } else {
            clientId = generateSessionId();
            clients.set(clientId, {
              ws,
              lastSeen: now,
              ip: ip,
              x: Math.random() * 500,
            });
            ws.send(JSON.stringify({ type: "init", sessionId: clientId }));
            broadcastViewerCount();
          }
          break;

        case "position":
          if (clientId && clients.has(clientId)) {
            clients.get(clientId).x = data.x;
            broadcastToOthers(
              JSON.stringify({
                type: "position",
                sessionId: clientId,
                x: data.x,
              }),
              clientId
            );
          }
          break;

        case "emotion":
          if (clientId && clients.has(clientId)) {
            if (!validateEmoji(data.emoji)) return;
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
            clients.get(clientId).lastSeen = now;
          }
          break;

        case "disconnect":
          if (clientId && clients.has(clientId)) {
            clients.delete(clientId);
            broadcastToOthers(
              JSON.stringify({
                type: "disconnect",
                sessionId: clientId,
              }),
              clientId
            );
            broadcastViewerCount();
          }
          break;
      }
    } catch (error) {
      logger.error("Message processing error:", error);
      ws.terminate();
    }
  });

  ws.on("close", () => {
    if (clientId && clients.has(clientId)) {
      clients.delete(clientId);
      ipConnections.set(ip, ipConnections.get(ip) - 1);
      if (ipConnections.get(ip) <= 0) {
        ipConnections.delete(ip);
      }
      broadcastToOthers(
        JSON.stringify({
          type: "disconnect",
          sessionId: clientId,
        }),
        clientId
      );
      broadcastViewerCount();
    }
  });

  ws.on("error", (error) => {
    logger.error(`WebSocket error for client ${clientId}:`, error);
    if (clientId && clients.has(clientId)) {
      clients.delete(clientId);
      broadcastViewerCount();
    }
  });
});

setInterval(() => {
  const now = Date.now();
  clients.forEach((client, id) => {
    if (
      now - client.lastSeen > CLEANUP_INTERVAL ||
      now - client.connectTime > MAX_CONNECTION_TIME
    ) {
      clients.delete(id);
      client.ws.close();
      broadcastToOthers(
        JSON.stringify({
          type: "disconnect",
          sessionId: id,
        }),
        id
      );
      broadcastViewerCount();
      logger.info(`Cleaned up connection: ${id}`);
    }
  });
}, HEARTBEAT_INTERVAL);

process.on("SIGTERM", () => {
  logger.info("SIGTERM received. Closing HTTP server...");
  server.close(() => {
    logger.info("HTTP server closed");
    wss.clients.forEach((client) => {
      client.terminate();
    });
    process.exit(0);
  });
});

process.on("SIGINT", () => {
  logger.info("SIGINT received. Closing HTTP server...");
  server.close(() => {
    logger.info("HTTP server closed");
    wss.clients.forEach((client) => {
      client.terminate();
    });
    process.exit(0);
  });
});

process.on("uncaughtException", (err) => {
  logger.error("Uncaught Exception:", err);
  setTimeout(() => {
    process.exit(1);
  }, 1000);
});

process.on("unhandledRejection", (reason, promise) => {
  logger.error("Unhandled Rejection at:", promise, "reason:", reason);
});

server.listen(PORT, "0.0.0.0", () => {
  logger.info(`Server running on port ${PORT}`);
});

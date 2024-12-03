const express = require("express");
const WebSocket = require("ws");
const { v4: uuidv4 } = require("uuid");
const winston = require("winston");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

// Configure logger
const logger = winston.createLogger({
  level: "info",
  format: winston.format.json(),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: "error.log", level: "error" }),
    new winston.transports.File({ filename: "combined.log" }),
  ],
});

// Constants
const PORT = process.env.PORT || 8080;
const MAX_CONNECTIONS = 10000;
const MAX_MESSAGE_SIZE = 1024;
const HEARTBEAT_INTERVAL = 30000;
const CLEANUP_INTERVAL = 60000;
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",")
  : ["https://5years-production.up.railway.app"];

// Express app setup
const app = express();
const server = require("http").createServer(app);

// Middleware
app.use(helmet());
app.use(express.json());
app.use(express.static("public"));

// CORS middleware
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", process.env.ALLOWED_ORIGINS);
  res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept"
  );
  next();
});

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).send("OK");
});

// WebSocket setup
const wss = new WebSocket.Server({
  server,
  path: "/ws",
});

const clients = new Map();

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});

// Utility functions
function generateSessionId() {
  return crypto.randomBytes(32).toString("hex");
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

function validateOrigin(origin) {
  return (
    process.env.NODE_ENV === "development" || ALLOWED_ORIGINS.includes(origin)
  );
}

// WebSocket connection handling
wss.on("connection", (ws, req) => {
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

  let clientId = null;

  ws.on("message", (message) => {
    try {
      if (message.length > MAX_MESSAGE_SIZE) {
        ws.terminate();
        logger.warn(`Message size exceeded from client ${clientId}`);
        return;
      }

      const data = JSON.parse(message);
      logger.info(`Received message: ${data.type} from: ${clientId}`);

      switch (data.type) {
        case "init":
          clientId = generateSessionId();
          clients.set(clientId, {
            ws,
            lastSeen: Date.now(),
            ip: req.headers["x-forwarded-for"] || req.socket.remoteAddress,
            x: data.x || Math.random() * 500,
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
          ws.send(
            JSON.stringify({
              type: "sync",
              avatars,
            })
          );

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
              lastSeen: Date.now(),
              ip: req.headers["x-forwarded-for"] || req.socket.remoteAddress,
              x: oldX,
            });
            broadcastViewerCount();
          } else {
            clientId = generateSessionId();
            clients.set(clientId, {
              ws,
              lastSeen: Date.now(),
              ip: req.headers["x-forwarded-for"] || req.socket.remoteAddress,
              x: Math.random() * 500,
            });
            ws.send(
              JSON.stringify({
                type: "init",
                sessionId: clientId,
              })
            );
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

// Cleanup interval
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
      logger.info(`Cleaned up stale connection: ${id}`);
    }
  });
}, HEARTBEAT_INTERVAL);

// Graceful shutdown handling
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

// Error handling
process.on("uncaughtException", (err) => {
  logger.error("Uncaught Exception:", err);
  setTimeout(() => {
    process.exit(1);
  }, 1000);
});

process.on("unhandledRejection", (reason, promise) => {
  logger.error("Unhandled Rejection at:", promise, "reason:", reason);
});

// Start server
server.listen(PORT, "0.0.0.0", () => {
  logger.info(`Server running on port ${PORT}`);
});

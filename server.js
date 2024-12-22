const express = require("express");
const WebSocket = require("ws");
const { v4: uuidv4 } = require("uuid");
const winston = require("winston");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const crypto = require("crypto");

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

const config = {
  PORT: process.env.PORT || 3000,
  MAX_CONNECTIONS: parseInt(process.env.MAX_CONNECTIONS, 10) || 100,
  MAX_MESSAGE_SIZE: parseInt(process.env.MAX_MESSAGE_SIZE, 10) || 1024 * 16,
  HEARTBEAT_INTERVAL: parseInt(process.env.HEARTBEAT_INTERVAL, 10) || 30000,
  CLEANUP_INTERVAL: parseInt(process.env.CLEANUP_INTERVAL, 10) || 60000,
  MAX_PLAYER_SPEED: parseInt(process.env.MAX_PLAYER_SPEED, 10) || 400,
  RATE_LIMIT_WINDOW: parseInt(process.env.RATE_LIMIT_WINDOW, 10) || 60000,
  RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX, 10) || 100,
  ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(",")
    : ["*"],
  NODE_ENV: process.env.NODE_ENV || "development",
};

class InputValidator {
  static validatePosition(x, y, bounds) {
    return {
      x: Math.max(0, Math.min(bounds.width, Number(x) || 0)),
      y: Math.max(0, Math.min(bounds.height, Number(y) || 0)),
    };
  }

  static validateAngle(angle) {
    const num = Number(angle);
    return isNaN(num) ? 0 : num;
  }

  static validateHealth(health) {
    return Math.max(0, Math.min(100, Number(health) || 0));
  }

  static validateShield(shield) {
    return Math.max(0, Math.min(100, Number(shield) || 0));
  }

  static sanitizeId(id) {
    return String(id).replace(/[^a-zA-Z0-9-_]/g, "");
  }

  static validateMessage(message, maxSize) {
    return (
      message &&
      typeof message === "object" &&
      JSON.stringify(message).length <= maxSize
    );
  }
}

class GameState {
  constructor() {
    this.clients = new Map();
    this.lastUpdate = Date.now();
    this.MAP_WIDTH = 2000;
    this.MAP_HEIGHT = 1500;
  }

  addClient(clientId, ws) {
    const bounds = { width: this.MAP_WIDTH, height: this.MAP_HEIGHT };
    const client = {
      ws,
      id: clientId,
      lastSeen: Date.now(),
      x: Math.random() * bounds.width,
      y: Math.random() * bounds.height,
      angle: 0,
      health: 100,
      shield: 100,
      isShielding: false,
      bounds,
      lastProcessedInput: 0,
      lastBroadcastTime: 0,
    };

    this.clients.set(clientId, client);
    return client;
  }

  removeClient(clientId) {
    this.clients.delete(clientId);
  }

  updateClientPosition(clientId, x, y, angle, inputSequence) {
    const client = this.clients.get(clientId);
    if (!client) return false;

    const now = Date.now();
    const timeSinceLastBroadcast = now - client.lastBroadcastTime;

    if (timeSinceLastBroadcast < 16) {
      return false;
    }

    const validPos = InputValidator.validatePosition(x, y, client.bounds);
    client.x = validPos.x;
    client.y = validPos.y;
    client.angle = InputValidator.validateAngle(angle);
    client.lastSeen = now;
    client.lastBroadcastTime = now;

    return true;
  }

  updateClientState(clientId, state) {
    const client = this.clients.get(clientId);
    if (!client) return false;

    let stateChanged = false;

    if (state.health !== undefined) {
      const newHealth = InputValidator.validateHealth(state.health);
      if (client.health !== newHealth) {
        client.health = newHealth;
        stateChanged = true;
      }
    }

    if (state.shield !== undefined) {
      const newShield = InputValidator.validateShield(state.shield);
      if (client.shield !== newShield) {
        client.shield = newShield;
        stateChanged = true;
      }
    }

    if (state.isShielding !== undefined) {
      const newShielding = Boolean(state.isShielding);
      if (client.isShielding !== newShielding) {
        client.isShielding = newShielding;
        stateChanged = true;
      }
    }

    client.lastSeen = Date.now();
    return stateChanged;
  }

  getClient(clientId) {
    return this.clients.get(clientId);
  }

  cleanup() {
    const now = Date.now();
    for (const [clientId, client] of this.clients.entries()) {
      if (now - client.lastSeen > config.CLEANUP_INTERVAL) {
        this.removeClient(clientId);
      }
    }
  }
}

const app = express();
const server = require("http").createServer(app);

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
  })
);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (config.ALLOWED_ORIGINS.includes("*")) {
    res.header("Access-Control-Allow-Origin", "*");
  } else if (config.ALLOWED_ORIGINS.includes(origin)) {
    res.header("Access-Control-Allow-Origin", origin);
  }
  res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept"
  );
  res.header("Access-Control-Allow-Credentials", "true");
  next();
});

app.use(
  rateLimit({
    windowMs: config.RATE_LIMIT_WINDOW,
    max: config.RATE_LIMIT_MAX,
  })
);

app.use(express.static(path.join(__dirname, "public")));

const wss = new WebSocket.Server({
  server,
  path: "/ws",
  clientTracking: true,
  perMessageDeflate: false,
  maxPayload: config.MAX_MESSAGE_SIZE,
  verifyClient: ({ origin }, callback) => {
    if (config.ALLOWED_ORIGINS.includes("*")) {
      callback(true);
    } else {
      callback(config.ALLOWED_ORIGINS.includes(origin));
    }
  },
});

const gameState = new GameState();

function validateOrigin(origin) {
  if (!origin || config.ALLOWED_ORIGINS.includes("*")) return true;
  return config.ALLOWED_ORIGINS.includes(origin.replace(/\/$/, ""));
}

function broadcastToOthers(message, excludeId) {
  const messageStr = JSON.stringify(message);
  gameState.clients.forEach((client, id) => {
    if (id !== excludeId && client.ws.readyState === WebSocket.OPEN) {
      try {
        client.ws.send(messageStr);
      } catch (error) {
        logger.error(`Broadcast error for client ${id}:`, error);
      }
    }
  });
}

function broadcastToAll(message) {
  const messageStr = JSON.stringify(message);
  gameState.clients.forEach((client) => {
    if (client.ws.readyState === WebSocket.OPEN) {
      try {
        client.ws.send(messageStr);
      } catch (error) {
        logger.error(`Broadcast error for client ${client.id}:`, error);
      }
    }
  });
}

function updatePlayerCount() {
  broadcastToAll({
    type: "players",
    count: gameState.clients.size,
  });
}

wss.on("connection", (ws, req) => {
  ws.isAlive = true;
  let clientId = null;

  const ping = () => {
    if (ws.isAlive === false) {
      ws.terminate();
      return;
    }
    ws.isAlive = false;
    try {
      ws.ping();
    } catch (error) {
      ws.terminate();
    }
  };

  const pingInterval = setInterval(ping, config.HEARTBEAT_INTERVAL);

  ws.on("pong", () => {
    ws.isAlive = true;
  });

  ws.on("message", (message) => {
    try {
      if (message.length > config.MAX_MESSAGE_SIZE) {
        ws.terminate();
        return;
      }

      const data = JSON.parse(message);
      if (!InputValidator.validateMessage(data, config.MAX_MESSAGE_SIZE)) {
        return;
      }

      switch (data.type) {
        case "init":
          clientId = uuidv4();
          const client = gameState.addClient(clientId, ws);

          if (data.screenWidth && data.screenHeight) {
            client.bounds = {
              width: Math.max(800, Math.min(3840, Number(data.screenWidth))),
              height: Math.max(600, Math.min(2160, Number(data.screenHeight))),
            };
          }

          ws.send(
            JSON.stringify({
              type: "init",
              sessionId: clientId,
              x: client.x,
              y: client.y,
            })
          );

          gameState.clients.forEach((existingClient, existingId) => {
            if (existingId !== clientId) {
              ws.send(
                JSON.stringify({
                  type: "playerJoined",
                  sessionId: existingId,
                  x: existingClient.x,
                  y: existingClient.y,
                  angle: existingClient.angle,
                  health: existingClient.health,
                  shield: existingClient.shield,
                  isShielding: existingClient.isShielding,
                })
              );
            }
          });

          broadcastToOthers(
            {
              type: "playerJoined",
              sessionId: clientId,
              x: client.x,
              y: client.y,
              angle: client.angle,
              health: client.health,
              shield: client.shield,
              isShielding: client.isShielding,
            },
            clientId
          );

          updatePlayerCount();
          break;

        case "position":
          if (!clientId) return;

          const positionResult = gameState.updateClientPosition(
            clientId,
            data.x,
            data.y,
            data.angle,
            data.inputSequence
          );

          if (positionResult) {
            broadcastToOthers(
              {
                type: "position",
                sessionId: clientId,
                x: data.x,
                y: data.y,
                angle: data.angle,
                timestamp: Date.now(),
              },
              clientId
            );
          }
          break;

        case "shoot":
          if (!clientId) return;

          const shooter = gameState.getClient(clientId);
          if (shooter) {
            broadcastToOthers(
              {
                type: "shoot",
                sessionId: clientId,
                x: data.x,
                y: data.y,
                angle: data.angle,
                timestamp: Date.now(),
              },
              clientId
            );
          }
          break;

        case "damage":
          if (!clientId) return;

          const target = gameState.getClient(data.targetId);
          if (target) {
            const damage = Math.min(100, Math.max(0, Number(data.amount) || 0));

            if (target.isShielding && target.shield > 0) {
              target.shield = Math.max(0, target.shield - damage * 0.5);
            } else {
              target.health = Math.max(0, target.health - damage);
            }

            broadcastToAll({
              type: "playerState",
              sessionId: data.targetId,
              health: target.health,
              shield: target.shield,
              isShielding: target.isShielding,
              x: target.x,
              y: target.y,
            });

            target.ws.send(
              JSON.stringify({
                type: "damage",
                amount: damage,
                sourceId: clientId,
                x: data.x,
                y: data.y,
              })
            );
          }
          break;

        case "shield":
          if (!clientId) return;

          const player = gameState.getClient(clientId);
          if (player) {
            player.isShielding = Boolean(data.active);
            broadcastToAll({
              type: "playerState",
              sessionId: clientId,
              health: player.health,
              shield: player.shield,
              isShielding: player.isShielding,
              x: player.x,
              y: player.y,
            });
          }
          break;

        case "disconnect":
          if (!clientId) return;
          cleanupClient();
          break;
      }
    } catch (error) {
      logger.error("Message processing error:", error);
    }
  });

  function cleanupClient() {
    if (clientId) {
      clearInterval(pingInterval);
      gameState.removeClient(clientId);
      broadcastToAll({
        type: "playerLeft",
        sessionId: clientId,
      });
      updatePlayerCount();
      clientId = null;
    }
  }

  ws.on("close", () => {
    cleanupClient();
  });

  ws.on("error", (error) => {
    logger.error(`WebSocket error for client ${clientId}:`, error);
    cleanupClient();
  });
});

server.listen(config.PORT, () => {
  logger.info(`Game server running on port ${config.PORT}`);
  logger.info(`Environment: ${config.NODE_ENV}`);
});

const cleanupInterval = setInterval(() => {
  try {
    gameState.cleanup();
    updatePlayerCount();
  } catch (error) {
    logger.error("Cleanup error:", error);
  }
}, config.CLEANUP_INTERVAL);

const heartbeatInterval = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, config.HEARTBEAT_INTERVAL);

async function gracefulShutdown(signal) {
  logger.info(`${signal} received. Starting graceful shutdown...`);

  clearInterval(cleanupInterval);
  clearInterval(heartbeatInterval);

  server.close(() => {
    wss.clients.forEach((client) => {
      try {
        client.close(1001, "Server shutting down");
      } catch (error) {
        logger.error("Error closing client connection:", error);
      }
    });

    wss.close(() => {
      logger.info("WebSocket server closed");

      logger.on("finish", () => {
        process.exit(0);
      });
      logger.end();
    });
  });

  setTimeout(() => {
    logger.error("Forced shutdown after timeout");
    process.exit(1);
  }, 10000);
}

process.on("SIGTERM", gracefulShutdown);
process.on("SIGINT", gracefulShutdown);

process.on("uncaughtException", (error) => {
  logger.error("Uncaught Exception:", error);
  gracefulShutdown("UNCAUGHT_EXCEPTION");
});

process.on("unhandledRejection", (reason, promise) => {
  logger.error("Unhandled Rejection at:", promise, "reason:", reason);
  gracefulShutdown("UNHANDLED_REJECTION");
});

app.get("/health", (req, res) => {
  res.status(200).json({
    status: "OK",
    uptime: process.uptime(),
    timestamp: Date.now(),
    wsConnections: wss.clients.size,
    environment: config.NODE_ENV,
    memoryUsage: process.memoryUsage(),
  });
});

app.get("/status", (req, res) => {
  const status = {
    server: {
      status: "running",
      uptime: process.uptime(),
      timestamp: Date.now(),
    },
    game: {
      players: gameState.clients.size,
      maxPlayers: config.MAX_CONNECTIONS,
      environment: config.NODE_ENV,
    },
    websocket: {
      connections: wss.clients.size,
      path: "/ws",
    },
  };
  res.json(status);
});

app.get("/ws", (req, res) => {
  res.set({
    Upgrade: "websocket",
    Connection: "Upgrade",
    "Sec-WebSocket-Version": "13",
  });
  res.status(426).send("Upgrade Required");
});

app.use((err, req, res, next) => {
  logger.error("Express error:", err);
  res.status(500).json({
    error: "Internal server error",
    timestamp: Date.now(),
  });
});

module.exports = {
  server,
  wss,
  gameState,
  config,
  logger,
  InputValidator,
  GameState,
};

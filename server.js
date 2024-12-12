const express = require("express");
const WebSocket = require("ws");
const { v4: uuidv4 } = require("uuid");
const winston = require("winston");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const crypto = require("crypto");

// Configure winston logger with custom format
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
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
    new winston.transports.File({
      filename: "combined.log",
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
  ],
});

// Environment configuration with defaults
const config = {
  PORT: process.env.PORT || 8080,
  MAX_CONNECTIONS: parseInt(process.env.MAX_CONNECTIONS, 10) || 100,
  MAX_MESSAGE_SIZE: parseInt(process.env.MAX_MESSAGE_SIZE, 10) || 1024,
  HEARTBEAT_INTERVAL: parseInt(process.env.HEARTBEAT_INTERVAL, 10) || 30000,
  CLEANUP_INTERVAL: parseInt(process.env.CLEANUP_INTERVAL, 10) || 60000,
  MAX_PLAYER_SPEED: parseInt(process.env.MAX_PLAYER_SPEED, 10) || 400,
  RATE_LIMIT_WINDOW: parseInt(process.env.RATE_LIMIT_WINDOW, 10) || 60000,
  RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX, 10) || 100,
  ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(",")
    : ["http://localhost:8080"],
  NODE_ENV: process.env.NODE_ENV || "development",
};

// Input validation utilities
const InputValidator = {
  validatePosition(x, y, bounds) {
    const validX = Math.max(0, Math.min(bounds.width, Number(x) || 0));
    const validY = Math.max(0, Math.min(bounds.height, Number(y) || 0));
    return { x: validX, y: validY };
  },

  validateAngle(angle) {
    const num = Number(angle);
    return isNaN(num) ? 0 : num;
  },

  validateHealth(health) {
    return Math.max(0, Math.min(100, Number(health) || 0));
  },

  validateShield(shield) {
    return Math.max(0, Math.min(100, Number(shield) || 0));
  },

  sanitizeId(id) {
    return String(id).replace(/[^a-zA-Z0-9-_]/g, "");
  },

  validateMessage(message, maxSize) {
    return (
      message &&
      typeof message === "object" &&
      JSON.stringify(message).length <= maxSize
    );
  },
};

// Rate limiter for specific game actions
class RateLimiter {
  constructor() {
    this.limits = new Map();
  }

  isAllowed(clientId, action) {
    if (!this.limits.has(clientId)) {
      this.limits.set(clientId, new Map());
    }

    const clientLimits = this.limits.get(clientId);
    if (!clientLimits.has(action)) {
      clientLimits.set(action, {
        count: 0,
        lastReset: Date.now(),
      });
    }

    const limit = clientLimits.get(action);
    const now = Date.now();

    // Reset counter if window has passed
    if (now - limit.lastReset > config.RATE_LIMIT_WINDOW) {
      limit.count = 0;
      limit.lastReset = now;
    }

    // Check if action is allowed
    const actionLimits = {
      position: 120,
      shoot: 10,
      shield: 1,
    };

    if (limit.count >= (actionLimits[action] || config.RATE_LIMIT_MAX)) {
      return false;
    }

    limit.count++;
    return true;
  }

  cleanup(clientId) {
    this.limits.delete(clientId);
  }
}

// Game state manager
class GameState {
  constructor() {
    this.clients = new Map();
    this.rateLimiter = new RateLimiter();
  }

  addClient(clientId, ws) {
    const client = {
      ws,
      lastSeen: Date.now(),
      x: 0,
      y: 0,
      angle: 0,
      health: 100,
      shield: 100,
      isShielding: false,
      bounds: {
        width: 800,
        height: 600,
      },
    };

    this.clients.set(clientId, client);
    return client;
  }

  removeClient(clientId) {
    this.clients.delete(clientId);
    this.rateLimiter.cleanup(clientId);
  }

  updateClientPosition(clientId, x, y, angle) {
    const client = this.clients.get(clientId);
    if (!client) return false;

    const validPos = InputValidator.validatePosition(x, y, client.bounds);
    client.x = validPos.x;
    client.y = validPos.y;
    client.angle = InputValidator.validateAngle(angle);
    client.lastSeen = Date.now();
    return true;
  }

  updateClientState(clientId, state) {
    const client = this.clients.get(clientId);
    if (!client) return false;

    if (state.health !== undefined) {
      client.health = InputValidator.validateHealth(state.health);
    }
    if (state.shield !== undefined) {
      client.shield = InputValidator.validateShield(state.shield);
    }
    if (state.isShielding !== undefined) {
      client.isShielding = Boolean(state.isShielding);
    }
    client.lastSeen = Date.now();
    return true;
  }

  getClient(clientId) {
    return this.clients.get(clientId);
  }

  validateAction(clientId, action) {
    return this.rateLimiter.isAllowed(clientId, action);
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

// Initialize Express app with security middleware
const app = express();
const server = require("http").createServer(app);

// Configure security middleware
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
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: true,
    crossOriginResourcePolicy: { policy: "same-site" },
    dnsPrefetchControl: true,
    frameguard: { action: "deny" },
    hidePoweredBy: true,
    hsts: true,
    ieNoOpen: true,
    noSniff: true,
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    xssFilter: true,
  })
);

// Rate limiting middleware
app.use(
  rateLimit({
    windowMs: config.RATE_LIMIT_WINDOW,
    max: config.RATE_LIMIT_MAX,
    message: "Too many requests from this IP",
  })
);

// Serve static files
app.use(express.static(path.join(__dirname, "public")));

// Initialize WebSocket server
const wss = new WebSocket.Server({ server });
const gameState = new GameState();

// WebSocket server functions
function validateOrigin(origin) {
  return (
    config.ALLOWED_ORIGINS.includes(origin) || config.NODE_ENV === "development"
  );
}

function broadcastToOthers(message, excludeId) {
  const messageStr = JSON.stringify(message);
  gameState.clients.forEach((client, id) => {
    if (id !== excludeId && client.ws.readyState === WebSocket.OPEN) {
      client.ws.send(messageStr);
    }
  });
}

function broadcastToAll(message) {
  const messageStr = JSON.stringify(message);
  gameState.clients.forEach((client) => {
    if (client.ws.readyState === WebSocket.OPEN) {
      client.ws.send(messageStr);
    }
  });
}

function updatePlayerCount() {
  broadcastToAll({
    type: "players",
    count: gameState.clients.size,
  });
}

function sendPlayerStates(ws, excludeId) {
  gameState.clients.forEach((client, id) => {
    if (id !== excludeId) {
      ws.send(
        JSON.stringify({
          type: "playerState",
          sessionId: id,
          x: client.x,
          y: client.y,
          health: client.health,
          shield: client.shield,
          isShielding: client.isShielding,
        })
      );
    }
  });
}

// WebSocket connection handler
wss.on("connection", (ws, req) => {
  if (!validateOrigin(req.headers.origin)) {
    ws.terminate();
    logger.warn(
      `Rejected connection from unauthorized origin: ${req.headers.origin}`
    );
    return;
  }

  if (gameState.clients.size >= config.MAX_CONNECTIONS) {
    ws.close(1013, "Maximum connections reached");
    logger.warn("Connection rejected: maximum connections reached");
    return;
  }

  let clientId = null;

  ws.on("message", (message) => {
    try {
      // Validate message size
      if (message.length > config.MAX_MESSAGE_SIZE) {
        ws.terminate();
        logger.warn(`Message size exceeded from client ${clientId}`);
        return;
      }

      const data = JSON.parse(message);
      if (!InputValidator.validateMessage(data, config.MAX_MESSAGE_SIZE)) {
        return;
      }

      // Handle different message types
      switch (data.type) {
        case "init":
          handleInitMessage(ws, data);
          break;
        case "position":
          handlePositionMessage(data);
          break;
        case "shoot":
          handleShootMessage(data);
          break;
        case "shield":
          handleShieldMessage(data);
          break;
        case "damage":
          handleDamageMessage(data);
          break;
        case "death":
          handleDeathMessage(data);
          break;
        case "disconnect":
          handleDisconnectMessage(data);
          break;
        case "heartbeat":
          handleHeartbeatMessage(data);
          break;
      }
    } catch (error) {
      logger.error("Message processing error:", error);
      ws.terminate();
    }
  });

  function handleInitMessage(ws, data) {
    clientId = uuidv4();
    const client = gameState.addClient(clientId, ws);

    // Set client bounds from initialization data
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
      })
    );

    sendPlayerStates(ws, clientId);
    updatePlayerCount();
  }

  function handlePositionMessage(data) {
    if (!clientId || !gameState.validateAction(clientId, "position")) return;

    if (gameState.updateClientPosition(clientId, data.x, data.y, data.angle)) {
      broadcastToOthers(
        {
          type: "position",
          sessionId: clientId,
          x: data.x,
          y: data.y,
          angle: data.angle,
        },
        clientId
      );
    }
  }

  function handleShootMessage(data) {
    if (!clientId || !gameState.validateAction(clientId, "shoot")) return;

    const client = gameState.getClient(clientId);
    if (client) {
      broadcastToOthers(
        {
          type: "shoot",
          sessionId: clientId,
          x: data.x,
          y: data.y,
          angle: data.angle,
        },
        clientId
      );
    }
  }

  function handleShieldMessage(data) {
    if (!clientId || !gameState.validateAction(clientId, "shield")) return;

    const client = gameState.getClient(clientId);
    if (client) {
      client.isShielding = Boolean(data.active);
      broadcastToAll({
        type: "playerState",
        sessionId: clientId,
        health: client.health,
        shield: client.shield,
        isShielding: client.isShielding,
        x: client.x,
        y: client.y,
      });
    }
  }

  function handleDamageMessage(data) {
    if (!clientId || !gameState.validateAction(clientId, "damage")) return;

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
        })
      );
    }
  }

  function handleDeathMessage(data) {
    if (!clientId) return;

    gameState.removeClient(clientId);
    broadcastToOthers(
      {
        type: "death",
        sessionId: clientId,
      },
      clientId
    );
    updatePlayerCount();
  }
  function handleDisconnectMessage(data) {
    if (!clientId) return;
    cleanupClient();
  }

  function handleHeartbeatMessage(data) {
    if (!clientId) return;
    const client = gameState.getClient(clientId);
    if (client) {
      client.lastSeen = Date.now();
    }
  }

  function cleanupClient() {
    if (clientId) {
      gameState.removeClient(clientId);
      broadcastToOthers(
        {
          type: "disconnect",
          sessionId: clientId,
        },
        clientId
      );
      updatePlayerCount();
      logger.info(`Client disconnected: ${clientId}`);
    }
  }

  // Connection event handlers
  ws.on("close", () => {
    cleanupClient();
  });

  ws.on("error", (error) => {
    logger.error(`WebSocket error for client ${clientId}:`, error);
    cleanupClient();
  });

  // Set up ping/pong for connection monitoring
  const pingInterval = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.ping(crypto.randomBytes(8));
    }
  }, config.HEARTBEAT_INTERVAL / 2);

  ws.on("pong", () => {
    const client = gameState.getClient(clientId);
    if (client) {
      client.lastSeen = Date.now();
    }
  });

  // Cleanup interval on client disconnect
  ws.on("close", () => {
    clearInterval(pingInterval);
  });
});

// Periodic game state cleanup
const cleanupInterval = setInterval(() => {
  try {
    gameState.cleanup();
    updatePlayerCount();
  } catch (error) {
    logger.error("Cleanup error:", error);
  }
}, config.CLEANUP_INTERVAL);

// Server startup and shutdown handling
server.listen(config.PORT, "0.0.0.0", () => {
  logger.info(`Game server running on port ${config.PORT}`);
  logger.info(`Environment: ${config.NODE_ENV}`);
  logger.info(`Max connections: ${config.MAX_CONNECTIONS}`);
});

// Graceful shutdown handlers
process.on("SIGTERM", gracefulShutdown);
process.on("SIGINT", gracefulShutdown);

async function gracefulShutdown(signal) {
  logger.info(`${signal} received. Starting graceful shutdown...`);

  // Stop accepting new connections
  server.close(async () => {
    logger.info("HTTP server closed");

    // Close all WebSocket connections
    wss.clients.forEach((client) => {
      client.close(1001, "Server shutting down");
    });

    // Clear intervals
    clearInterval(cleanupInterval);

    // Wait for WebSocket server to close
    await new Promise((resolve) => {
      wss.close(() => {
        logger.info("WebSocket server closed");
        resolve();
      });
    });

    // Close logger transports
    await new Promise((resolve) => {
      logger.on("finish", resolve);
      logger.end();
    });

    process.exit(0);
  });

  // Force shutdown after timeout
  setTimeout(() => {
    logger.error("Forced shutdown after timeout");
    process.exit(1);
  }, 10000);
}

// Unhandled error handlers
process.on("uncaughtException", (error) => {
  logger.error("Uncaught Exception:", error);
  gracefulShutdown("UNCAUGHT_EXCEPTION");
});

process.on("unhandledRejection", (reason, promise) => {
  logger.error("Unhandled Rejection at:", promise, "reason:", reason);
});

// Health check endpoint
app.get("/health", (req, res) => {
  const health = {
    uptime: process.uptime(),
    status: "OK",
    timestamp: Date.now(),
    connections: wss.clients.size,
    memory: process.memoryUsage(),
    environment: config.NODE_ENV,
  };

  res.json(health);
});

// Monitoring endpoints (protected by basic auth in production)
if (config.NODE_ENV === "production") {
  const auth = require("express-basic-auth");
  const adminAuth = auth({
    users: {
      [process.env.ADMIN_USER || "admin"]: process.env.ADMIN_PASS || "changeme",
    },
    challenge: true,
  });

  app.get("/metrics", adminAuth, (req, res) => {
    const metrics = {
      players: {
        total: gameState.clients.size,
        active: Array.from(gameState.clients.values()).filter(
          (c) => Date.now() - c.lastSeen < config.HEARTBEAT_INTERVAL
        ).length,
      },
      performance: {
        memory: process.memoryUsage(),
        cpu: process.cpuUsage(),
        uptime: process.uptime(),
      },
      rateLimiting: {
        windowMs: config.RATE_LIMIT_WINDOW,
        max: config.RATE_LIMIT_MAX,
      },
      errors: {
        lastError: logger.getLastError?.() || null,
      },
    };

    res.json(metrics);
  });

  app.get("/status", adminAuth, (req, res) => {
    const status = {
      server: {
        status: "running",
        version: process.env.npm_package_version || "1.0.0",
        nodeVersion: process.version,
        uptime: process.uptime(),
      },
      game: {
        players: gameState.clients.size,
        maxPlayers: config.MAX_CONNECTIONS,
      },
      system: {
        memory: process.memoryUsage(),
        platform: process.platform,
        arch: process.arch,
      },
    };

    res.json(status);
  });
}

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error("Express error:", err);
  res.status(500).json({ error: "Internal server error" });
});

module.exports = {
  server,
  wss,
  gameState,
  config,
  logger,
};

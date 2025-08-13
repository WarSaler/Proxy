const express = require('express');
const http = require('http');
const net = require('net');
const url = require('url');
const cron = require('node-cron');
const axios = require('axios');
const winston = require('winston');
const helmet = require('helmet');
const cors = require('cors');
const WebSocket = require('ws');

// Настройка логирования
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'proxy.log' })
  ]
});

const app = express();
const PORT = parseInt(process.env.PORT) || 10000;
const SOCKS_PORT = parseInt(process.env.SOCKS_PORT) || PORT; // Use same port on Render

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Статистика подключений
let stats = {
  totalConnections: 0,
  activeConnections: 0,
  socksConnections: 0,
  httpConnections: 0,
  startTime: new Date()
};

// Health check endpoint для предотвращения засыпания на Render
app.get('/health', (req, res) => {
  const uptime = Math.floor((Date.now() - stats.startTime.getTime()) / 1000);
  res.json({
    status: 'ok',
    uptime: uptime,
    stats: stats,
    timestamp: new Date().toISOString()
  });
  logger.info('Health check requested');
});

// Информационная страница
app.get('/', (req, res) => {
  res.json({
    name: 'Universal Messenger Proxy',
    description: 'Прокси-сервер для Telegram и WhatsApp',
    features: [
      'SOCKS5 прокси для Telegram (порт ' + SOCKS_PORT + ')',
      'HTTP CONNECT прокси для WhatsApp (порт ' + PORT + ')',
      'Keep-alive система для Render',
      'Статистика подключений'
    ],
    usage: {
      telegram: {
        type: 'SOCKS5',
        host: process.env.RENDER_EXTERNAL_URL || 'localhost',
        port: SOCKS_PORT
      },
      whatsapp: {
        type: 'HTTP CONNECT',
        host: process.env.RENDER_EXTERNAL_URL || 'localhost',
        port: PORT,
        note: 'Настройте системный прокси на устройстве'
      }
    },
    stats: stats
  });
});

// Статистика
app.get('/stats', (req, res) => {
  res.json(stats);
});

// HTTP CONNECT прокси для WhatsApp и других приложений
const server = http.createServer(app);

server.on('connect', (req, clientSocket, head) => {
  const { hostname, port } = url.parse(`http://${req.url}`);
  
  logger.info(`HTTP CONNECT request to ${hostname}:${port}`);
  stats.totalConnections++;
  stats.activeConnections++;
  stats.httpConnections++;

  const serverSocket = net.connect(port || 80, hostname, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    serverSocket.write(head);
    serverSocket.pipe(clientSocket);
    clientSocket.pipe(serverSocket);
  });

  serverSocket.on('error', (err) => {
    logger.error(`Server socket error: ${err.message}`);
    clientSocket.end();
    stats.activeConnections--;
  });

  clientSocket.on('error', (err) => {
    logger.error(`Client socket error: ${err.message}`);
    serverSocket.end();
    stats.activeConnections--;
  });

  clientSocket.on('close', () => {
    stats.activeConnections--;
    serverSocket.end();
  });

  serverSocket.on('close', () => {
    stats.activeConnections--;
    clientSocket.end();
  });
});

// SOCKS5 прокси для Telegram
class SOCKS5Server {
  constructor(port) {
    this.port = port;
    this.server = net.createServer();
    this.setupServer();
  }

  setupServer() {
    this.server.on('connection', (socket) => {
      logger.info('New SOCKS5 connection');
      stats.totalConnections++;
      stats.activeConnections++;
      stats.socksConnections++;
      
      // Set socket state
      socket.socksState = 'init';
      socket.setTimeout(60000); // 60 second timeout
      
      socket.on('data', (data) => {
        try {
          this.handleSocksData(socket, data);
        } catch (err) {
          logger.error(`Error handling SOCKS data: ${err.message}`);
          socket.destroy();
        }
      });

      socket.on('close', () => {
        if (socket.socksState !== 'tunneling') {
          stats.activeConnections--;
        }
        logger.info('SOCKS5 connection closed');
      });

      socket.on('error', (err) => {
        logger.error(`SOCKS5 socket error: ${err.message}`);
        if (socket.socksState !== 'tunneling') {
          stats.activeConnections--;
        }
        socket.destroy();
      });

      socket.on('timeout', () => {
        logger.info('SOCKS5 socket timeout');
        socket.destroy();
      });
    });
  }

  handleSocksData(socket, data) {
    if (data.length < 2) {
      logger.warn(`Insufficient data length: ${data.length}`);
      return;
    }

    // Check if this is HTTP request (common issue on Render)
    const dataStr = data.toString('ascii', 0, Math.min(data.length, 10));
    if (dataStr.startsWith('GET ') || dataStr.startsWith('POST ') || dataStr.startsWith('HEAD ')) {
      logger.warn(`HTTP request received on SOCKS port: ${dataStr}`);
      socket.write('HTTP/1.1 400 Bad Request\r\n\r\nThis is a SOCKS5 proxy, not HTTP');
      socket.destroy();
      return;
    }

    const version = data[0];
    logger.info(`Received SOCKS data: version=${version}, length=${data.length}, state=${socket.socksState}, hex=${data.toString('hex')}`);
    
    if (version !== 5) {
      logger.error(`Unsupported SOCKS version: ${version}, expected 5. Data: ${data.toString('hex')}`);
      socket.destroy();
      return;
    }

    // Handle authentication phase
    if (socket.socksState === 'init') {
      if (data.length >= 3) {
        const nmethods = data[1];
        if (data.length >= 2 + nmethods) {
          // Send "no authentication required" response
          socket.write(Buffer.from([5, 0]));
          socket.socksState = 'auth_done';
          logger.info('SOCKS5 authentication completed');
          return;
        }
      }
      return;
    }
    
    // Handle connection request phase
    if (socket.socksState === 'auth_done') {
      if (data.length >= 4) {
        const cmd = data[1];
        const rsv = data[2];
        const atyp = data[3];
        
        if (cmd !== 1) {
          // Command not supported
          const response = Buffer.from([5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
          socket.write(response);
          socket.destroy();
          return;
        }
        
        let hostname, port;

        if (atyp === 1) { // IPv4
          if (data.length >= 10) {
            hostname = `${data[4]}.${data[5]}.${data[6]}.${data[7]}`;
            port = data.readUInt16BE(8);
          }
        } else if (atyp === 3) { // Domain name
          if (data.length >= 5) {
            const domainLength = data[4];
            if (data.length >= 5 + domainLength + 2) {
              hostname = data.slice(5, 5 + domainLength).toString();
              port = data.readUInt16BE(5 + domainLength);
            }
          }
        } else if (atyp === 4) { // IPv6
          if (data.length >= 22) {
            const ipv6Parts = [];
            for (let i = 0; i < 16; i += 2) {
              ipv6Parts.push(data.readUInt16BE(4 + i).toString(16));
            }
            hostname = ipv6Parts.join(':');
            port = data.readUInt16BE(20);
          }
        }

        if (hostname && port) {
          socket.socksState = 'connecting';
          logger.info(`SOCKS5 connection request to ${hostname}:${port}`);
          this.connectToTarget(socket, hostname, port);
        } else {
          logger.error('Invalid SOCKS5 connection request');
          const response = Buffer.from([5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
          socket.write(response);
          socket.destroy();
        }
      }
      return;
    }
    
    // If we reach here, the socket is in an unexpected state
    logger.error(`Unexpected SOCKS5 data in state: ${socket.socksState}`);
  }

  connectToTarget(clientSocket, hostname, port) {
    logger.info(`SOCKS5 connecting to ${hostname}:${port}`);
    
    const targetSocket = net.connect(port, hostname, () => {
      // Send success response
      const response = Buffer.from([
        5, 0, 0, 1, // SOCKS5, success, reserved, IPv4
        0, 0, 0, 0, // IP address (0.0.0.0)
        0, 0 // Port (0)
      ]);
      
      try {
        clientSocket.write(response);
        
        // Set socket state to tunneling
        clientSocket.socksState = 'tunneling';
        
        // Remove all previous listeners to avoid conflicts
        clientSocket.removeAllListeners('data');
        
        // Pipe data between client and target
        targetSocket.pipe(clientSocket, { end: false });
        clientSocket.pipe(targetSocket, { end: false });
        
        logger.info(`SOCKS5 tunnel established to ${hostname}:${port}`);
      } catch (err) {
        logger.error(`Error establishing tunnel: ${err.message}`);
        targetSocket.destroy();
        clientSocket.destroy();
      }
    });

    targetSocket.on('error', (err) => {
      logger.error(`Target socket error for ${hostname}:${port}: ${err.message}`);
      try {
        const response = Buffer.from([5, 1, 0, 1, 0, 0, 0, 0, 0, 0]); // Connection refused
        if (!clientSocket.destroyed) {
          clientSocket.write(response);
          clientSocket.end();
        }
      } catch (writeErr) {
        logger.error(`Error writing error response: ${writeErr.message}`);
        clientSocket.destroy();
      }
    });

    clientSocket.on('close', () => {
      if (!targetSocket.destroyed) {
        targetSocket.destroy();
      }
      stats.activeConnections--;
      logger.info(`SOCKS5 client disconnected from ${hostname}:${port}`);
    });

    targetSocket.on('close', () => {
      if (!clientSocket.destroyed) {
        clientSocket.destroy();
      }
      logger.info(`SOCKS5 target disconnected from ${hostname}:${port}`);
    });

    clientSocket.on('error', (err) => {
      logger.error(`Client socket error: ${err.message}`);
      if (!targetSocket.destroyed) {
        targetSocket.destroy();
      }
      stats.activeConnections--;
    });

    // Set timeout for connection
    const connectionTimeout = setTimeout(() => {
      logger.error(`Connection timeout to ${hostname}:${port}`);
      targetSocket.destroy();
      if (!clientSocket.destroyed) {
        const response = Buffer.from([5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
        try {
          clientSocket.write(response);
          clientSocket.end();
        } catch (err) {
          clientSocket.destroy();
        }
      }
    }, 30000); // 30 second timeout

    targetSocket.on('connect', () => {
      clearTimeout(connectionTimeout);
    });
  }

  handleConnection(socket, initialData) {
    logger.info('Handling existing SOCKS5 connection');
    stats.totalConnections++;
    stats.activeConnections++;
    stats.socksConnections++;
    
    // Set socket state
    socket.socksState = 'init';
    socket.setTimeout(60000);
    
    // Handle initial data
    try {
      this.handleSocksData(socket, initialData);
    } catch (err) {
      logger.error(`Error handling initial SOCKS data: ${err.message}`);
      socket.destroy();
    }
    
    // Set up event handlers
    socket.on('data', (data) => {
      try {
        this.handleSocksData(socket, data);
      } catch (err) {
        logger.error(`Error handling SOCKS data: ${err.message}`);
        socket.destroy();
      }
    });

    socket.on('close', () => {
      if (socket.socksState !== 'tunneling') {
        stats.activeConnections--;
      }
      logger.info('SOCKS5 connection closed');
    });

    socket.on('error', (err) => {
      logger.error(`SOCKS5 socket error: ${err.message}`);
      if (socket.socksState !== 'tunneling') {
        stats.activeConnections--;
      }
      socket.destroy();
    });

    socket.on('timeout', () => {
      logger.info('SOCKS5 socket timeout');
      socket.destroy();
    });
  }

  listen() {
    this.server.listen(this.port, () => {
      logger.info(`SOCKS5 server listening on port ${this.port}`);
    });
  }
}

// Создаем отдельный TCP сервер для SOCKS5 на том же порту
let socksServer = new SOCKS5Server(SOCKS_PORT);

// HTTP SOCKS5 туннель - эмулируем SOCKS5 через HTTP
app.use('/socks5-tunnel', (req, res) => {
  logger.info('SOCKS5 HTTP tunnel request received');
  
  // Устанавливаем заголовки для бинарного потока
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Transfer-Encoding', 'chunked');
  res.setHeader('Connection', 'keep-alive');
  
  let isHandshakeComplete = false;
  let targetSocket = null;
  
  // Обрабатываем входящие данные от клиента
  req.on('data', (data) => {
    try {
      logger.info(`SOCKS5 tunnel data: ${data.toString('hex').substring(0, 20)}...`);
      
      if (!isHandshakeComplete && data[0] === 5) {
        // SOCKS5 handshake
        if (data.length >= 3 && data[1] === 1 && data[2] === 0) {
          // Отвечаем: версия 5, метод 0 (без аутентификации)
          res.write(Buffer.from([5, 0]));
          logger.info('SOCKS5 handshake completed');
          return;
        }
        
        // SOCKS5 connect request
        if (data.length >= 10 && data[1] === 1) {
          const addrType = data[3];
          let hostname, port, offset;
          
          if (addrType === 1) {
            // IPv4
            hostname = `${data[4]}.${data[5]}.${data[6]}.${data[7]}`;
            port = (data[8] << 8) | data[9];
            offset = 10;
          } else if (addrType === 3) {
            // Domain name
            const domainLen = data[4];
            hostname = data.slice(5, 5 + domainLen).toString();
            port = (data[5 + domainLen] << 8) | data[6 + domainLen];
            offset = 7 + domainLen;
          }
          
          logger.info(`SOCKS5 connecting to ${hostname}:${port}`);
          
          // Создаем соединение с целевым сервером
          targetSocket = net.connect(port, hostname, () => {
            // Отправляем успешный ответ SOCKS5
            const response = Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
            res.write(response);
            isHandshakeComplete = true;
            logger.info(`SOCKS5 tunnel established to ${hostname}:${port}`);
            
            // Пересылаем данные между клиентом и сервером
            targetSocket.on('data', (serverData) => {
              res.write(serverData);
            });
            
            targetSocket.on('close', () => {
              logger.info('Target connection closed');
              res.end();
            });
            
            targetSocket.on('error', (err) => {
              logger.error(`Target connection error: ${err.message}`);
              res.end();
            });
          });
          
          targetSocket.on('error', (err) => {
            logger.error(`Failed to connect to ${hostname}:${port}: ${err.message}`);
            const errorResponse = Buffer.from([5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
            res.write(errorResponse);
            res.end();
          });
        }
      } else if (isHandshakeComplete && targetSocket) {
        // Пересылаем данные на целевой сервер
        targetSocket.write(data);
      }
    } catch (err) {
      logger.error(`SOCKS5 tunnel error: ${err.message}`);
      res.end();
    }
  });
  
  req.on('close', () => {
    logger.info('SOCKS5 tunnel client disconnected');
    if (targetSocket) {
      targetSocket.destroy();
    }
  });
  
  req.on('error', (err) => {
    logger.error(`SOCKS5 tunnel request error: ${err.message}`);
    if (targetSocket) {
      targetSocket.destroy();
    }
  });
});

// Информация о SOCKS5 туннеле
app.get('/socks5', (req, res) => {
  res.json({
    message: 'HTTP SOCKS5 Tunnel Proxy',
    endpoint: `https://${req.get('host')}/socks5-tunnel`,
    protocol: 'SOCKS5 over HTTP',
    usage: 'Configure as HTTP proxy with CONNECT method support',
    telegram_settings: {
      type: 'HTTP',
      server: req.get('host'),
      port: 443,
      note: 'Use HTTPS proxy settings in Telegram'
    }
  });
});

// Запускаем HTTP сервер на основном порту
server.listen(PORT, () => {
  logger.info(`HTTP server with SOCKS5 tunnel listening on port ${PORT}`);
  logger.info(`SOCKS5 tunnel endpoint: https://proxy-j2ht.onrender.com/socks5-tunnel`);
  logger.info(`Universal Messenger Proxy started`);
  logger.info(`HTTP CONNECT proxy listening on port ${PORT}`);
  logger.info(`SOCKS5 over HTTP tunnel available at /socks5-tunnel`);
  logger.info(`Health check available at /health`);
  
  if (process.env.RENDER_EXTERNAL_URL) {
    logger.info(`External URL: ${process.env.RENDER_EXTERNAL_URL}`);
  }
});

// Запускаем SOCKS5 сервер на отдельном порту (если доступен)
if (process.env.SOCKS_PORT && process.env.SOCKS_PORT !== process.env.PORT) {
  socksServer.listen();
  logger.info(`Traditional SOCKS5 server listening on separate port ${SOCKS_PORT}`);
} else {
  logger.info('Traditional SOCKS5 disabled - using HTTP SOCKS5 tunnel for Render compatibility');
}

// Keep-alive система для предотвращения засыпания на Render
if (process.env.RENDER_EXTERNAL_URL) {
  // Пинг каждые 2 минуты для предотвращения засыпания
  cron.schedule('*/2 * * * *', async () => {
    try {
      const response = await axios.get(`${process.env.RENDER_EXTERNAL_URL}/health`, {
        timeout: 10000
      });
      logger.info(`Keep-alive ping successful: ${response.status}`);
    } catch (error) {
      logger.error(`Keep-alive ping failed: ${error.message}`);
    }
  });
  
  logger.info('Keep-alive system activated for Render');
}

// HTTP сервер уже запущен выше с полным логированием

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('Received SIGTERM, shutting down gracefully');
  server.close(() => {
    socksServer.server.close(() => {
      process.exit(0);
    });
  });
});

process.on('SIGINT', () => {
  logger.info('Received SIGINT, shutting down gracefully');
  server.close(() => {
    socksServer.server.close(() => {
      process.exit(0);
    });
  });
});
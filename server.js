const express = require('express');
const http = require('http');
const net = require('net');
const url = require('url');
const cron = require('node-cron');
const axios = require('axios');
const winston = require('winston');
const helmet = require('helmet');
const cors = require('cors');

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
const PORT = process.env.PORT || 3000;
const SOCKS_PORT = process.env.SOCKS_PORT || 1080;

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
      
      socket.on('data', (data) => {
        this.handleSocksData(socket, data);
      });

      socket.on('close', () => {
        stats.activeConnections--;
      });

      socket.on('error', (err) => {
        logger.error(`SOCKS5 socket error: ${err.message}`);
        stats.activeConnections--;
      });
    });
  }

  handleSocksData(socket, data) {
    if (data.length < 2) return;

    const version = data[0];
    if (version === 5) {
      if (data[1] === 1 && data.length >= 3) {
        // Authentication request
        socket.write(Buffer.from([5, 0])); // No authentication required
      } else if (data[1] === 1 && data.length > 3) {
        // Connection request
        const cmd = data[1];
        const atyp = data[3];
        
        if (cmd === 1) { // CONNECT command
          let hostname, port;
          let offset = 4;

          if (atyp === 1) { // IPv4
            hostname = `${data[4]}.${data[5]}.${data[6]}.${data[7]}`;
            port = data.readUInt16BE(8);
          } else if (atyp === 3) { // Domain name
            const domainLength = data[4];
            hostname = data.slice(5, 5 + domainLength).toString();
            port = data.readUInt16BE(5 + domainLength);
          }

          if (hostname && port) {
            this.connectToTarget(socket, hostname, port);
          }
        }
      }
    }
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
      clientSocket.write(response);
      
      // Pipe data between client and target
      targetSocket.pipe(clientSocket);
      clientSocket.pipe(targetSocket);
    });

    targetSocket.on('error', (err) => {
      logger.error(`Target socket error: ${err.message}`);
      const response = Buffer.from([5, 1, 0, 1, 0, 0, 0, 0, 0, 0]); // Connection refused
      clientSocket.write(response);
      clientSocket.end();
    });

    clientSocket.on('close', () => {
      targetSocket.end();
    });

    targetSocket.on('close', () => {
      clientSocket.end();
    });
  }

  listen() {
    this.server.listen(this.port, () => {
      logger.info(`SOCKS5 server listening on port ${this.port}`);
    });
  }
}

// Запуск SOCKS5 сервера
const socksServer = new SOCKS5Server(SOCKS_PORT);
socksServer.listen();

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

// Запуск HTTP сервера
server.listen(PORT, () => {
  logger.info(`Universal Messenger Proxy started`);
  logger.info(`HTTP CONNECT proxy listening on port ${PORT}`);
  logger.info(`SOCKS5 proxy listening on port ${SOCKS_PORT}`);
  logger.info(`Health check available at /health`);
  
  if (process.env.RENDER_EXTERNAL_URL) {
    logger.info(`External URL: ${process.env.RENDER_EXTERNAL_URL}`);
  }
});

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
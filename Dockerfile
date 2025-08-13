# Используем официальный Node.js образ
FROM node:18-alpine

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем package.json и package-lock.json (если есть)
COPY package*.json ./

# Устанавливаем зависимости
RUN npm install --only=production

# Копируем исходный код
COPY . .

# Создаем пользователя для безопасности
RUN addgroup -g 1001 -S nodejs
RUN adduser -S proxy -u 1001

# Меняем владельца файлов
RUN chown -R proxy:nodejs /app
USER proxy

# Открываем порты
EXPOSE 3000 1080

# Команда запуска
CMD ["node", "server.js"]
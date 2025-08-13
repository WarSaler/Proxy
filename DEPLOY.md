# 🚀 Быстрое развертывание на Render

Пошаговая инструкция для развертывания универсального прокси-сервера на Render.com

## Шаг 1: Подготовка репозитория

### Создание репозитория на GitHub

1. Зайдите на [GitHub.com](https://github.com)
2. Нажмите "New repository"
3. Название: `universal-messenger-proxy` (или любое другое)
4. Сделайте репозиторий **публичным** (для бесплатного тарифа Render)
5. Нажмите "Create repository"

### Загрузка кода

```bash
# В папке с проектом
git init
git add .
git commit -m "Initial commit: Universal proxy server"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/universal-messenger-proxy.git
git push -u origin main
```

## Шаг 2: Создание сервиса на Render

### Регистрация и подключение

1. Зайдите на [Render.com](https://render.com)
2. Зарегистрируйтесь или войдите в аккаунт
3. Нажмите "New +" → "Web Service"
4. Подключите ваш GitHub аккаунт (если еще не подключен)
5. Выберите репозиторий `universal-messenger-proxy`

### Настройка сервиса

**Основные настройки:**
- **Name:** `universal-messenger-proxy` (или ваше название)
- **Region:** `Oregon (US West)` (рекомендуется)
- **Branch:** `main`
- **Runtime:** `Docker`
- **Plan:** `Free`

**Build & Deploy:**
- **Build Command:** `npm ci`
- **Start Command:** `npm start`

### Переменные окружения

В разделе "Environment Variables" добавьте:

```
NODE_ENV=production
PORT=3000
SOCKS_PORT=1080
RENDER_EXTERNAL_URL=https://your-app-name.onrender.com
```

> ⚠️ Замените `your-app-name` на реальное название вашего сервиса

## Шаг 3: Деплой

1. Нажмите "Create Web Service"
2. Дождитесь завершения деплоя (5-10 минут)
3. Проверьте статус: `https://your-app-name.onrender.com/health`

## Шаг 4: Настройка Keep-Alive

### UptimeRobot (рекомендуется)

1. Зайдите на [UptimeRobot.com](https://uptimerobot.com)
2. Зарегистрируйтесь (бесплатно)
3. "Add New Monitor":
   - **Monitor Type:** HTTP(s)
   - **Friendly Name:** `Proxy Keep-Alive`
   - **URL:** `https://your-app-name.onrender.com/health`
   - **Monitoring Interval:** 5 minutes
4. Нажмите "Create Monitor"

### Альтернатива: cron-job.org

1. Зайдите на [cron-job.org](https://cron-job.org)
2. Зарегистрируйтесь
3. "Create cronjob":
   - **Title:** `Proxy Keep-Alive`
   - **Address:** `https://your-app-name.onrender.com/health`
   - **Schedule:** Every 5 minutes
4. Сохраните задачу

## Шаг 5: Проверка работы

### Тестирование эндпоинтов

```bash
# Health check
curl https://your-app-name.onrender.com/health

# Информация о сервисе
curl https://your-app-name.onrender.com/

# Статистика
curl https://your-app-name.onrender.com/stats
```

### Проверка портов

```bash
# Проверка SOCKS5 порта (должен быть доступен)
telnet your-app-name.onrender.com 1080

# Проверка HTTP порта
telnet your-app-name.onrender.com 3000
```

## Шаг 6: Настройка клиентов

### Данные для подключения

**SOCKS5 (Telegram):**
- Сервер: `your-app-name.onrender.com`
- Порт: `1080`
- Без авторизации

**HTTP (WhatsApp):**
- Сервер: `your-app-name.onrender.com`
- Порт: `3000`

## 🔧 Обновление кода

Для обновления сервера:

```bash
# Внесите изменения в код
git add .
git commit -m "Update: описание изменений"
git push origin main
```

Render автоматически пересоберет и задеплоит новую версию.

## 📊 Мониторинг

### Логи Render

1. Зайдите в Dashboard Render
2. Выберите ваш сервис
3. Вкладка "Logs" - здесь отображаются все логи сервера

### Метрики

- **Events** - история деплоев
- **Metrics** - использование CPU, памяти, сети
- **Settings** - настройки сервиса

## ⚠️ Важные моменты

### Ограничения бесплатного тарифа

- **750 часов в месяц** (достаточно для 24/7)
- **Засыпание через 15 минут** без активности
- **Время пробуждения:** 2-3 минуты
- **1 одновременный деплой**

### Рекомендации

1. **Обязательно настройте keep-alive** (UptimeRobot)
2. **Мониторьте использование часов** в Dashboard
3. **Делайте backup конфигурации** клиентов
4. **Тестируйте после каждого обновления**

### Upgrade до Starter ($7/месяц)

Преимущества:
- Нет засыпания
- Больше ресурсов CPU/RAM
- Приоритетная поддержка
- Кастомные домены

## 🆘 Решение проблем

### Деплой не удался

1. Проверьте логи в Render Dashboard
2. Убедитесь, что все файлы загружены в репозиторий
3. Проверьте синтаксис в `package.json` и `Dockerfile`

### Сервис недоступен

1. Проверьте статус в Dashboard
2. Посмотрите логи на наличие ошибок
3. Убедитесь, что keep-alive работает
4. Попробуйте Manual Deploy

### Клиенты не подключаются

1. Проверьте доступность портов
2. Убедитесь, что сервис не спит
3. Проверьте правильность настроек в клиентах
4. Попробуйте другой регион Render

## 📞 Поддержка

Если возникли проблемы:

1. Проверьте логи сервера
2. Убедитесь в правильности всех настроек
3. Создайте issue в GitHub репозитории
4. Обратитесь в поддержку Render (для проблем с платформой)

---

**Готово!** Ваш универсальный прокси-сервер развернут и готов к использованию. 🎉
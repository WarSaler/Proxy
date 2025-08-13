# 📱 Настройка клиентов

Подробные инструкции по настройке Telegram и WhatsApp для работы с прокси-сервером

## 🔧 Данные для подключения

После развертывания на Render у вас будут следующие данные:

```
Сервер: your-app-name.onrender.com
SOCKS5 порт: 1080 (для Telegram)
HTTP порт: 3000 (для WhatsApp)
Авторизация: не требуется
```

> ⚠️ Замените `your-app-name` на реальное название вашего сервиса в Render

---

# 📱 Telegram

## Android

### Способ 1: Через настройки

1. **Откройте Telegram**
2. **Меню** (☰ в левом верхнем углу)
3. **Настройки** → **Данные и память**
4. Прокрутите вниз до **"Настройки прокси"**
5. Нажмите **"Добавить прокси"**
6. Выберите **"SOCKS5"**
7. **Заполните поля:**
   ```
   Сервер: your-app-name.onrender.com
   Порт: 1080
   Имя пользователя: (оставьте пустым)
   Пароль: (оставьте пустым)
   ```
8. **Сохраните** и **включите прокси**
9. ✅ **Включите "Использовать прокси для звонков"**

### Способ 2: По ссылке

Вы можете создать ссылку для быстрой настройки:
```
https://t.me/socks?server=your-app-name.onrender.com&port=1080
```

## iOS

1. **Откройте Telegram**
2. **Настройки** (шестеренка внизу справа)
3. **Данные и память** → **Прокси**
4. **Добавить прокси** → **SOCKS5**
5. **Заполните данные:**
   ```
   Сервер: your-app-name.onrender.com
   Порт: 1080
   Имя пользователя: (пусто)
   Пароль: (пусто)
   ```
6. **Сохранить** → **Использовать прокси**

## Windows (Telegram Desktop)

1. **Откройте Telegram Desktop**
2. **Настройки** (⚙️) → **Дополнительно**
3. **Тип соединения** → **Использовать пользовательский прокси**
4. Выберите **"SOCKS5"**
5. **Введите данные:**
   ```
   Hostname: your-app-name.onrender.com
   Port: 1080
   Username: (пусто)
   Password: (пусто)
   ```
6. **Сохранить**

## macOS (Telegram Desktop)

1. **Telegram** → **Preferences** (⌘,)
2. **Advanced** → **Connection type**
3. **Use custom proxy** → **SOCKS5**
4. **Заполните поля:**
   ```
   Hostname: your-app-name.onrender.com
   Port: 1080
   Username: (пусто)
   Password: (пусто)
   ```
5. **Save**

## Linux (Telegram Desktop)

1. **Settings** → **Advanced** → **Connection type**
2. **Use custom proxy** → **SOCKS5**
3. **Введите данные сервера**
4. **Apply**

---

# 💬 WhatsApp

> ⚠️ **Важно:** WhatsApp не поддерживает встроенные настройки прокси. Необходимо настроить системный прокси или использовать специальные приложения.

## Android

### Способ 1: Системный прокси Wi-Fi

1. **Настройки** → **Wi-Fi**
2. **Нажмите и удерживайте** название вашей сети
3. **Изменить сеть** → **Дополнительные параметры**
4. **Прокси** → **Вручную**
5. **Заполните:**
   ```
   Имя хоста прокси: your-app-name.onrender.com
   Порт прокси: 3000
   ```
6. **Сохранить**
7. **Перезапустите WhatsApp**

### Способ 2: Приложения прокси

#### ProxyDroid (требует root)
1. Установите **ProxyDroid** из Google Play
2. **Настройки:**
   ```
   Host: your-app-name.onrender.com
   Port: 3000
   Proxy Type: HTTP
   ```
3. **Включите прокси**

#### Every Proxy (без root)
1. Установите **Every Proxy**
2. **HTTP Proxy:**
   ```
   Server: your-app-name.onrender.com
   Port: 3000
   ```
3. **Start** → разрешите VPN подключение

### Способ 3: Drony (рекомендуется)
1. Установите **Drony** из Google Play
2. **Settings** → **Network** → **WiFi**
3. Выберите вашу сеть → **Manual proxy**
4. **Proxy type:** HTTP
5. **Hostname:** `your-app-name.onrender.com`
6. **Port:** `3000`
7. **ON** → разрешите VPN

## iOS

### Системный прокси

1. **Настройки** → **Wi-Fi**
2. **Нажмите (i)** рядом с вашей сетью
3. **Настроить прокси** → **Вручную**
4. **Заполните:**
   ```
   Сервер: your-app-name.onrender.com
   Порт: 3000
   Аутентификация: Выкл
   ```
5. **Сохранить**
6. **Перезапустите WhatsApp**

### Приложения прокси

#### Shadowrocket (платное)
1. Купите **Shadowrocket** в App Store
2. **Добавить конфигурацию** → **HTTP**
3. **Сервер:** `your-app-name.onrender.com:3000`
4. **Подключиться**

#### Potatso Lite (бесплатное)
1. Установите **Potatso Lite**
2. **Add** → **Manual Input**
3. **Type:** HTTP
4. **Server:** `your-app-name.onrender.com`
5. **Port:** `3000`
6. **Start**

## Windows

### Системный прокси

1. **Настройки** (Win + I) → **Сеть и Интернет**
2. **Прокси** → **Настройка прокси вручную**
3. **Использовать прокси-сервер** → **Включить**
4. **Заполните:**
   ```
   Адрес: your-app-name.onrender.com
   Порт: 3000
   ```
5. ✅ **Не использовать прокси-сервер для локальных адресов**
6. **Сохранить**
7. **Перезапустите WhatsApp**

### Через браузер (WhatsApp Web)

#### Chrome с прокси
```bash
# Создайте ярлык Chrome с параметрами:
"C:\Program Files\Google\Chrome\Application\chrome.exe" --proxy-server="http://your-app-name.onrender.com:3000" --user-data-dir="C:\temp\chrome_proxy"
```

#### Firefox
1. **Настройки** → **Основные** → **Параметры сети**
2. **Ручная настройка прокси**
3. **HTTP прокси:**
   ```
   your-app-name.onrender.com
   Порт: 3000
   ```
4. ✅ **Использовать этот прокси для HTTPS**
5. **ОК**

## macOS

### Системный прокси

1. **Системные настройки** → **Сеть**
2. Выберите активное подключение → **Дополнительно**
3. **Прокси** → ✅ **Веб-прокси (HTTP)**
4. **Заполните:**
   ```
   Сервер веб-прокси: your-app-name.onrender.com
   Порт: 3000
   ```
5. ✅ **Защищенный веб-прокси (HTTPS)** (те же данные)
6. **ОК** → **Применить**

### Через Terminal (для разработчиков)
```bash
# Установить прокси для текущей сессии
export http_proxy=http://your-app-name.onrender.com:3000
export https_proxy=http://your-app-name.onrender.com:3000

# Запустить WhatsApp через прокси
open -a "WhatsApp"
```

## Linux

### Системный прокси (GNOME)

1. **Настройки** → **Сеть** → **Прокси**
2. **Ручная настройка**
3. **HTTP прокси:**
   ```
   your-app-name.onrender.com:3000
   ```
4. **HTTPS прокси:** (те же данные)
5. **Применить системно**

### Через переменные окружения
```bash
# Добавьте в ~/.bashrc или ~/.zshrc
export http_proxy="http://your-app-name.onrender.com:3000"
export https_proxy="http://your-app-name.onrender.com:3000"
export HTTP_PROXY="http://your-app-name.onrender.com:3000"
export HTTPS_PROXY="http://your-app-name.onrender.com:3000"

# Перезагрузите конфигурацию
source ~/.bashrc

# Запустите WhatsApp
whatsapp-for-linux  # или другой клиент
```

### Proxychains (для любых приложений)
```bash
# Установите proxychains
sudo apt install proxychains4  # Ubuntu/Debian
sudo pacman -S proxychains-ng  # Arch

# Настройте /etc/proxychains4.conf
echo "http your-app-name.onrender.com 3000" | sudo tee -a /etc/proxychains4.conf

# Запустите WhatsApp через прокси
proxychains4 whatsapp-for-linux
```

---

# 🔍 Проверка работы

## Тестирование подключения

### Telegram
1. Откройте любой чат
2. Отправьте сообщение
3. Попробуйте голосовой/видеозвонок
4. В настройках прокси должен быть статус "Подключен"

### WhatsApp
1. Откройте WhatsApp
2. Проверьте статус "Онлайн"
3. Отправьте сообщение
4. Попробуйте голосовой звонок

## Диагностика проблем

### Проверка доступности сервера
```bash
# Проверка HTTP порта
curl -I http://your-app-name.onrender.com:3000

# Проверка SOCKS5 порта
telnet your-app-name.onrender.com 1080

# Проверка через прокси
curl --proxy socks5://your-app-name.onrender.com:1080 https://api.telegram.org
```

### Логи и отладка
1. Проверьте логи сервера: `https://your-app-name.onrender.com/stats`
2. Убедитесь, что сервер не спит: `https://your-app-name.onrender.com/health`
3. Проверьте настройки клиента
4. Попробуйте отключить и включить прокси

---

# 📋 Чек-лист настройки

## Telegram ✅
- [ ] Прокси добавлен в настройки
- [ ] Тип: SOCKS5
- [ ] Сервер и порт указаны правильно
- [ ] Прокси включен
- [ ] "Использовать для звонков" включено
- [ ] Сообщения отправляются
- [ ] Звонки работают

## WhatsApp ✅
- [ ] Системный прокси настроен ИЛИ приложение прокси установлено
- [ ] Тип: HTTP
- [ ] Сервер и порт указаны правильно
- [ ] WhatsApp перезапущен
- [ ] Статус "Онлайн" отображается
- [ ] Сообщения отправляются
- [ ] Звонки работают

## Сервер ✅
- [ ] Сервис развернут на Render
- [ ] Health check отвечает: `/health`
- [ ] Keep-alive настроен (UptimeRobot)
- [ ] Статистика доступна: `/stats`
- [ ] Логи не показывают ошибок

---

**Готово!** Ваши мессенджеры настроены для работы через прокси-сервер. 🎉
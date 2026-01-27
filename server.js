const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Порт: локально 3000, на Render — тот, который он даёт
const PORT = process.env.PORT || 3000;

// Подключение к PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

// Секрет для сессий (лучше задать переменную среды SESSION_SECRET на Render)
const SESSION_SECRET =
  process.env.SESSION_SECRET || "очень_длинная_строка_для_сессий_123";

// Инициализация БД (создаём таблицу пользователей, если её нет)
async function initDb() {
  // Таблица пользователей
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
    );
  `);

  // Таблица сообщений общего чата
  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      author TEXT NOT NULL,
      text TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  
// Таблица чатов
await pool.query(`
  CREATE TABLE IF NOT EXISTS chats (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW()
  );
`);

// Участники чатов
await pool.query(`
  CREATE TABLE IF NOT EXISTS chat_members (
    chat_id INTEGER REFERENCES chats(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (chat_id, user_id)
  );
`);

  console.log("База данных инициализирована (users + messages готовы)");
}

initDb().catch((err) => {
  console.error("Ошибка инициализации БД:", err);
});

// Чтобы читать данные из форм
app.use(express.urlencoded({ extended: true }));

// Сессии: теперь в Postgres, а не в памяти
app.use(
  session({
    store: new pgSession({
      pool: pool, // наш Pool к Postgres
      tableName: "session",
      createTableIfMissing: true,
    }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 дней
      sameSite: "lax",
      secure: false, // за прокси Render можно оставить false
    },
  })
);

// ======= ДАННЫЕ ЧАТА (сообщения пока в памяти) =======
let messages = []; // { author, text, time }

// ======= РОУТ ДЛЯ ЧАТА (ПРОВЕРКА ВХОДА) =======

app.get("/chat", (req, res) => {
  if (!req.session.user) {
    // Если не вошёл — отправляем на логин
    return res.redirect("/login.html");
  }
  res.sendFile(path.join(__dirname, "public", "chat.html"));
});

// Статические файлы (главная, логин, регистрация, стили и т.п.)
app.use(express.static(path.join(__dirname, "public")));

// ======= РЕГИСТРАЦИЯ (с хешированием пароля, в БД) =======

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.send(
      "Логин и пароль обязательны. <a href='/register.html'>Назад</a>"
    );
  }

  try {
    const existing = await pool.query(
      "SELECT id FROM users WHERE username = $1",
      [username]
    );

    if (existing.rowCount > 0) {
      return res.send(
        "Такой логин уже занят. <a href='/register.html'>Попробовать другой</a>"
      );
    }

    const passwordHash = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users (username, password_hash) VALUES ($1, $2)",
      [username, passwordHash]
    );

    console.log("Новый пользователь зарегистрирован:", username);
    res.redirect("/login.html");
  } catch (err) {
    console.error("Ошибка при регистрации:", err);
    res.send("Ошибка сервера. Попробуйте позже.");
  }
});

// ======= ВХОД (логин) =======

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query(
      "SELECT id, username, password_hash FROM users WHERE username = $1",
      [username]
    );

    if (result.rowCount === 0) {
      return res.send(
        "Неверный логин или пароль. <a href='/login.html'>Попробовать снова</a>"
      );
    }

    const user = result.rows[0];

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.send(
        "Неверный логин или пароль. <a href='/login.html'>Попробовать снова</a>"
      );
    }

    // Сохраняем юзера в сессию
    req.session.user = { id: user.id, username: user.username };

    console.log("Пользователь вошёл:", user.username);
    res.redirect("/chat");
  } catch (err) {
    console.error("Ошибка при входе:", err);
    res.send("Ошибка сервера. Попробуйте позже.");
  }
});

// ======= ЭНДПОИНТ /me ДЛЯ ФРОНТА (кто я) =======

app.get("/me", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ loggedIn: false });
  }
  res.json({
    loggedIn: true,
    id: req.session.user.id,
    username: req.session.user.username,
  });
});

// ======= ВЫХОД =======

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login.html");
  });
});

// ======= УДАЛЕНИЕ АККАУНТА =======

app.post("/delete-account", async (req, res) => {
  if (!req.session.user) {
    return res.redirect("/login.html");
  }

  const userId = req.session.user.id;

  try {
    await pool.query("DELETE FROM users WHERE id = $1", [userId]);
    console.log("Пользователь удалён:", userId);

    req.session.destroy(() => {
      res.redirect("/register.html");
    });
  } catch (err) {
    console.error("Ошибка при удалении аккаунта:", err);
    res.send(
      "Не удалось удалить аккаунт. Попробуйте позже. <a href='/chat'>Назад в чат</a>"
    );
  }
});

// ======= SOCKET.IO (общий чат с БД сообщений) =======

io.on("connection", (socket) => {
  console.log("Новое соединение:", socket.id);

  // При подключении отправляем последние 100 сообщений из БД
  (async () => {
    try {
      const result = await pool.query(
        `
        SELECT
          author,
          text,
          to_char(created_at, 'HH24:MI') AS time
        FROM messages
        ORDER BY created_at ASC
        LIMIT 100;
      `
      );

      socket.emit("chat-history", result.rows);
    } catch (err) {
      console.error("Ошибка загрузки истории сообщений:", err);
    }
  })();

  // Получаем новое сообщение от клиента
  socket.on("chat-message", async (msg) => {
    if (!msg || !msg.author || !msg.text) return;

    try {
      // Сохраняем сообщение в БД
      const insertResult = await pool.query(
        `
        INSERT INTO messages (author, text)
        VALUES ($1, $2)
        RETURNING
          author,
          text,
          to_char(created_at, 'HH24:MI') AS time;
      `,
        [msg.author, msg.text]
      );

      const savedMsg = insertResult.rows[0];

      // Рассылаем всем уже сохранённое сообщение (с нормальным time)
      io.emit("chat-message", savedMsg);
    } catch (err) {
      console.error("Ошибка при сохранении сообщения:", err);
    }
  });

  socket.on("disconnect", () => {
    console.log("Отключился:", socket.id);
  });
});

// ======= ЗАПУСК СЕРВЕРА =======

server.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});




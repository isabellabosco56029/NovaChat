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
app.use(express.json());

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

// ======= ИНФОРМАЦИЯ О ТЕКУЩЕМ ПОЛЬЗОВАТЕЛЕ =======

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


// ======= СПИСОК ЛИЧНЫХ ЧАТОВ ПОЛЬЗОВАТЕЛЯ =======

app.get("/chats/list", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ ok: false, error: "Не авторизован" });
  }

  const userId = req.session.user.id;

  try {
    const result = await pool.query(
      `
      SELECT
        c.id,
        c.created_at,
        u.username AS peer_username
      FROM chats c
      JOIN chat_members cm_self
        ON cm_self.chat_id = c.id
      JOIN chat_members cm_peer
        ON cm_peer.chat_id = c.id AND cm_peer.user_id <> cm_self.user_id
      JOIN users u
        ON u.id = cm_peer.user_id
      WHERE cm_self.user_id = $1
      ORDER BY c.created_at DESC;
      `,
      [userId]
    );

    res.json({ ok: true, chats: result.rows });
  } catch (err) {
    console.error("Ошибка при получении списка чатов:", err);
    res.status(500).json({ ok: false, error: "Ошибка сервера" });
  }
});


// ======= СОЗДАНИЕ ЛИЧНОГО ЧАТА ПО ЛОГИНУ =======

app.post("/chats/new", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ ok: false, error: "Не авторизован" });
  }

  const myId = req.session.user.id;
  const { username } = req.body;

  if (!username) {
    return res
      .status(400)
      .json({ ok: false, error: "Укажите логин пользователя" });
  }

  try {
    // Получаем свой логин
    const selfUser = await pool.query(
      "SELECT username FROM users WHERE id = $1",
      [myId]
    );

    // Запрет чата с самим собой
    if (
      selfUser.rowCount > 0 &&
      selfUser.rows[0].username === username
    ) {
      return res
        .status(400)
        .json({ ok: false, error: "Нельзя создать чат с самим собой" });
    }

    // Ищем другого пользователя
    const other = await pool.query(
      "SELECT id, username FROM users WHERE username = $1",
      [username]
    );

    if (other.rowCount === 0) {
      return res
        .status(404)
        .json({ ok: false, error: "Пользователь не найден" });
    }

    const otherId = other.rows[0].id;

    // Проверяем, есть ли уже чат
    const existing = await pool.query(
      `
      SELECT c.id
      FROM chats c
      JOIN chat_members cm1 ON cm1.chat_id = c.id AND cm1.user_id = $1
      JOIN chat_members cm2 ON cm2.chat_id = c.id AND cm2.user_id = $2
      LIMIT 1;
      `,
      [myId, otherId]
    );

    if (existing.rowCount > 0) {
      return res.json({
        ok: true,
        existing: true,
        chatId: existing.rows[0].id,
        peerUsername: other.rows[0].username,
      });
    }

    // Создаём новый чат
    const chatInsert = await pool.query(
      "INSERT INTO chats DEFAULT VALUES RETURNING id"
    );

    const chatId = chatInsert.rows[0].id;

    await pool.query(
      `
      INSERT INTO chat_members (chat_id, user_id)
      VALUES ($1, $2), ($1, $3);
      `,
      [chatId, myId, otherId]
    );

    res.json({
      ok: true,
      existing: false,
      chatId,
      peerUsername: other.rows[0].username,
    });
  } catch (err) {
    console.error("Ошибка при создании чата:", err);
    res.status(500).json({ ok: false, error: "Ошибка сервера" });
  }
});


// ======= ВЫХОД И УДАЛЕНИЕ АККАУНТА =======

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login.html");
  });
});

app.post("/delete-account", async (req, res) => {
  if (!req.session.user) {
    return res.redirect("/login.html");
  }

  try {
    await pool.query("DELETE FROM users WHERE id = $1", [
      req.session.user.id,
    ]);
    req.session.destroy(() => {
      res.redirect("/register.html");
    });
  } catch (err) {
    console.error(err);
    res.send("Ошибка при удалении аккаунта");
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






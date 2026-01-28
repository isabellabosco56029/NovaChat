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

// ======= SOCKET.IO: комнаты для личных чатов =======
io.on("connection", (socket) => {
  console.log("Socket connected", socket.id);

  // Пользователь заходит в чат
  socket.on("join-chat", (chatId) => {
    if (!chatId) return;
    socket.join(`chat:${chatId}`);
  });

  // Пользователь уходит из чата
  socket.on("leave-chat", (chatId) => {
    if (!chatId) return;
    socket.leave(`chat:${chatId}`);
  });

  socket.on("disconnect", () => {
    console.log("Socket disconnected:", socket.id);
  });
});

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

// ======= ИНИЦИАЛИЗАЦИЯ БД =======
async function initDb() {
  // 1. Пользователи
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
    );
  `);

  // 2. Чаты
  await pool.query(`
    CREATE TABLE IF NOT EXISTS chats (
      id SERIAL PRIMARY KEY,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // 3. Участники чатов
  await pool.query(`
    CREATE TABLE IF NOT EXISTS chat_members (
      chat_id INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      PRIMARY KEY (chat_id, user_id)
    );
  `);

  // 4. Сообщения — WARNING: сейчас пересоздаётся при старте
  await pool.query(`DROP TABLE IF EXISTS messages;`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      chat_id INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
      author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE SET NULL,
      text TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  console.log(
    "База данных инициализирована (users, chats, chat_members, messages готовы)"
  );
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
      pool: pool,
      tableName: "session",
      createTableIfMissing: true,
    }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 дней
      sameSite: "lax",
      secure: false,
    },
  })
);

// ======= РОУТ ДЛЯ ЧАТА (ПРОВЕРКА ВХОДА) =======
app.get("/chat", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/login.html");
  }
  res.sendFile(path.join(__dirname, "public", "chat.html"));
});

// Статика
app.use(express.static(path.join(__dirname, "public")));

// ======= РЕГИСТРАЦИЯ =======
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

// ======= ВХОД =======
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

    req.session.user = { id: user.id, username: user.username };

    console.log("Пользователь вошёл:", user.username);
    res.redirect("/chat");
  } catch (err) {
    console.error("Ошибка при входе:", err);
    res.send("Ошибка сервера. Попробуйте позже.");
  }
});

// ======= /me =======
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

// ======= СПИСОК ЛИЧНЫХ ЧАТОВ =======
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

// ======= СОЗДАНИЕ ЛИЧНОГО ЧАТА =======
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
    // логин текущего пользователя
    const selfUser = await pool.query(
      "SELECT username FROM users WHERE id = $1",
      [myId]
    );

    if (selfUser.rowCount > 0 && selfUser.rows[0].username === username) {
      return res
        .status(400)
        .json({ ok: false, error: "Нельзя создать чат с самим собой" });
    }

    // другой пользователь
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

    // есть ли уже чат между ними
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

    // создаём новый чат
    const chatInsert = await pool.query(
      "INSERT INTO chats DEFAULT VALUES RETURNING id, created_at"
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

// ======= ПОЛУЧЕНИЕ СООБЩЕНИЙ ЧАТА =======
app.get("/chats/:chatId/messages", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ ok: false, error: "Не авторизован" });
  }

  const userId = req.session.user.id;
  const chatId = parseInt(req.params.chatId, 10);

  if (!chatId || Number.isNaN(chatId)) {
    return res.status(400).json({ ok: false, error: "Некорректный chatId" });
  }

  try {
    const memberCheck = await pool.query(
      "SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2 LIMIT 1;",
      [chatId, userId]
    );

    if (memberCheck.rowCount === 0) {
      return res
        .status(403)
        .json({ ok: false, error: "У вас нет доступа к этому чату" });
    }

    const result = await pool.query(
      `
      SELECT
        m.id,
        u.username AS author,
        m.text,
        to_char(m.created_at, 'HH24:MI') AS time
      FROM messages m
      JOIN users u ON u.id = m.author_id
      WHERE m.chat_id = $1
      ORDER BY m.created_at ASC
      LIMIT 200;
      `,
      [chatId]
    );

    res.json({ ok: true, messages: result.rows });
  } catch (err) {
    console.error("Ошибка при получении сообщений:", err);
    res.status(500).json({ ok: false, error: "Ошибка сервера" });
  }
});

// ======= ОТПРАВКА СООБЩЕНИЯ В ЧАТ =======
app.post("/chats/:chatId/messages", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ ok: false, error: "Не авторизован" });
  }

  const userId = req.session.user.id;
  const chatId = parseInt(req.params.chatId, 10);
  const { text } = req.body;

  if (!chatId || Number.isNaN(chatId)) {
    return res.status(400).json({ ok: false, error: "Некорректный chatId" });
  }

  if (!text || !text.trim()) {
    return res
      .status(400)
      .json({ ok: false, error: "Текст сообщения не может быть пустым" });
  }

  try {
    // Проверяем, что пользователь участник чата
    const memberCheck = await pool.query(
      "SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2 LIMIT 1;",
      [chatId, userId]
    );

    if (memberCheck.rowCount === 0) {
      return res
        .status(403)
        .json({ ok: false, error: "У вас нет доступа к этому чату" });
    }

    const insertResult = await pool.query(
      `
      INSERT INTO messages (chat_id, author_id, text)
      VALUES ($1, $2, $3)
      RETURNING id, text, created_at;
      `,
      [chatId, userId, text.trim()]
    );

    const row = insertResult.rows[0];

    const userResult = await pool.query(
      "SELECT username FROM users WHERE id = $1;",
      [userId]
    );
    const authorUsername =
      userResult.rowCount > 0 ? userResult.rows[0].username : "Unknown";

    const msg = {
      id: row.id,
      chatId,
      author: authorUsername,
      text: row.text,
      time: new Date(row.created_at).toLocaleTimeString("ru-RU", {
        hour: "2-digit",
        minute: "2-digit",
      }),
    };

    // Отправляем сообщение всем участникам этого чата
    io.to(`chat:${chatId}`).emit("chat:new-message", msg);

    return res.json({ ok: true });
  } catch (err) {
    console.error("Ошибка при отправке сообщения:", err);
    return res.status(500).json({ ok: false, error: "Ошибка сервера" });
  }
});

// ======= УДАЛЕНИЕ СООБЩЕНИЯ =======
app.delete("/chats/:chatId/messages/:messageId", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ ok: false, error: "Не авторизован" });
  }

  const userId = req.session.user.id;
  const chatId = parseInt(req.params.chatId, 10);
  const messageId = parseInt(req.params.messageId, 10);

  if (!chatId || Number.isNaN(chatId)) {
    return res.status(400).json({ ok: false, error: "Некорректный chatId" });
  }

  if (!messageId || Number.isNaN(messageId)) {
    return res.status(400).json({ ok: false, error: "Некорректный messageId" });
  }

  try {
    const memberCheck = await pool.query(
      "SELECT 1 FROM chat_members WHERE chat_id = $1 AND user_id = $2 LIMIT 1;",
      [chatId, userId]
    );

    if (memberCheck.rowCount === 0) {
      return res
        .status(403)
        .json({ ok: false, error: "У вас нет доступа к этому чату" });
    }

    const deleteResult = await pool.query(
      `
      DELETE FROM messages
      WHERE id = $1 AND chat_id = $2 AND author_id = $3
      RETURNING id;
      `,
      [messageId, chatId, userId]
    );

    if (deleteResult.rowCount === 0) {
      return res.status(404).json({
        ok: false,
        error: "Сообщение не найдено или у вас нет прав на удаление",
      });
    }

    io.to(`chat:${chatId}`).emit("chat:delete-message", {
      chatId,
      messageId,
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error("Ошибка при удалении сообщения:", err);
    return res.status(500).json({ ok: false, error: "Ошибка сервера" });
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
    await pool.query("DELETE FROM users WHERE id = $1", [req.session.user.id]);
    req.session.destroy(() => {
      res.redirect("/register.html");
    });
  } catch (err) {
    console.error(err);
    res.send("Ошибка при удалении аккаунта");
  }
});

// ======= ЗАПУСК СЕРВЕРА =======
server.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});

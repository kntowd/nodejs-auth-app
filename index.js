const express = require("express");
const jwt = require("jsonwebtoken");
const { v4: uuid } = require("uuid");
const cookieParser = require("cookie-parser");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const sendPasswordResetMail = require("./externalApi/sendPasswordResetMail");

const port = 3000;

const app = express();

app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const pool = new Pool({
  user: "postgres",
  host: "127.0.0.1",
  database: "auth_app_db",
  password: "password",
  port: 5432,
});

const isExpiredToken = (tokenCreatedDateString) => {
  const now = new Date().getTime();
  const tokenCreatedDate = new Date(tokenCreatedDateString).getTime();
  const tokenElapsedHour = (now - tokenCreatedDate) / (60 * 60 * 1000);
  return tokenElapsedHour > 1;
};

// ログインページを表示する
app.get("/login", (req, res) => {
  res.render("login");
});

// 新規登録ページを表示する
app.get("/register", (req, res) => {
  res.render("register");
});

// 新規登録を処理する
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  const userId = uuid();
  const hashedPassword = await bcrypt.hash(password, 10);

  const connect = await pool.connect();
  await connect.query(
    "INSERT INTO users (id, name, email, password ) VALUES($1, $2, $3, $4)",
    [userId, name, email, hashedPassword]
  );
  connect.release();

  // JWTトークンを作成する
  const token = jwt.sign({ userId }, "secret");

  // JWTトークンをクライアントに送信する
  res.cookie("token", token, { httpOnly: true });
  res.redirect("/dashboard");
});

// ログインを処理する
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const connect = await pool.connect();
  const { rows } = await connect.query("SELECT * FROM users WHERE email=$1", [
    email,
  ]);
  await connect.release();

  if (rows.length <= 0) {
    return res.status(401).json({ message: "認証に失敗しました" });
  }

  if (!bcrypt.compareSync(password, rows[0].password)) {
    return res
      .status(401)
      .json({ message: "メールアドレスまたはパスワードが間違っています" });
  }

  const token = jwt.sign({ userId: rows[0].id }, "secret");

  res.cookie("token", token, { httpOnly: true });

  if (req.cookies.redirect) {
    res.clearCookie("redirect");
    return res.redirect(req.cookies.redirect);
  }

  res.redirect("/dashboard");
});

app.get("/dashboard", async (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    res.cookie("redirect", "/dashboard");
    return res.redirect("/login");
  }

  try {
    jwt.verify(token, "secret");
  } catch (err) {
    return res.redirect("/login");
  }

  res.render("dashboard");
});

app.get("/password-reset", async (req, res) => {
  res.render("passwordResetMailSend");
});

app.get("/password-reset/:token", async (req, res) => {
  const token = req.params.token;

  const connect = await pool.connect();
  const { rows: passwordResettings } = await connect.query(
    "SELECT * FROM password_resettings WHERE token=$1 ORDER BY created_at DESC LIMIT 1",
    [token]
  );

  if (passwordResettings.length < 1) {
    return res.status(400).json({ message: "存在しないページです" });
  }

  if (isExpiredToken(passwordResettings[0].created_at)) {
    return res
      .status(400)
      .json({ message: "パスワード更新用リンクの期限が切れています" });
  }

  await connect.release();
  res.render("passwordReset", { token });
});

app.post("/password-reset/send-mail", async (req, res) => {
  const { email } = req.body;
  const passwordResetToken = uuid();

  const connect = await pool.connect();

  const { rows: users } = await connect.query(
    "SELECT * FROM users WHERE email=$1",
    [email]
  );

  if (users.length <= 0) return res.render("passwordResetMailSent", { email });

  await connect.query(
    "INSERT INTO password_resettings (token, email) VALUES ($1,$2)",
    [passwordResetToken, email]
  );
  await connect.release();

  // パスワード再設定用メールを送信する
  sendPasswordResetMail(passwordResetToken);

  res.render("passwordResetMailSent", { email });
});

app.post("/password-reset/:token", async (req, res) => {
  const { password } = req.body;
  const token = req.params.token;

  const connect = await pool.connect();

  const { rows: passwordResettings } = await connect.query(
    "SELECT * FROM password_resettings WHERE token=$1 ORDER BY created_at DESC LIMIT 1",
    [token]
  );

  if (passwordResettings.length < 1) {
    return res.status(500).json({ message: "internal server error." });
  }

  if (isExpiredToken(passwordResettings[0].created_at)) {
    return res
      .status(400)
      .json({ message: "パスワード更新用リンクの期限が切れています" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  await connect.query("UPDATE users SET password=$1 WHERE email=$2", [
    hashedPassword,
    passwordResettings[0].email,
  ]);

  await connect.release();

  res.render("passwordResetCompleted");
});

app.get("/test", async (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    res.cookie("redirect", "/test");
    return res.redirect("/login");
  }

  try {
    jwt.verify(token, "secret");
  } catch (err) {
    return res.redirect("/login");
  }

  res.render("test");
});

app.listen(port, () => {
  console.log(`auth app listening on port ${port}`);
});

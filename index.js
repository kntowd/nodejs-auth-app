const express = require("express");
const jwt = require("jsonwebtoken");
const { v4: uuid } = require("uuid");
const cookieParser = require("cookie-parser");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");

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

// ログインページを表示する
app.get("/login", (req, res) => {
  res.render("login");
});

// 新規登録ページを表示する
app.get("/register", (req, res) => {
  console.log("register");
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
  connect.release();

  if (bcrypt.compareSync(password, rows[0].password)) {
    return res
      .status(401)
      .json({ msg: "メールアドレスまたはパスワードが間違っています" });
  }

  if (rows.length <= 0) {
    return res.status(401).json({ msg: "認証に失敗しました" });
  }

  const token = jwt.sign({ userId: rows[0].id }, "secret");

  res.cookie("token", token, { httpOnly: true });
  res.redirect("/dashboard");
});

app.get("/dashboard", async (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.redirect("/login");
  }

  try {
    jwt.verify(token, "secret");
  } catch (err) {
    return res.redirect("/login");
  }

  res.render("dashboard");
});

app.listen(port, () => {
  console.log(`auth app listening on port ${port}`);
});

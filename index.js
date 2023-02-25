const express = require("express");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const port = 3000;

const app = express();

app.set("view engine", "ejs");

app.use(express.json());
app.use(cookieParser());

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
app.post("/register", (req, res) => {
  const { name, email, password } = req.body;

  // JWTトークンを作成する
  const token = jwt.sign({ userId: "hoge" }, "secret");

  // JWTトークンをクライアントに送信する
  res.cookie("token", token, { httpOnly: true });
  res.redirect("/dashboard");
});

// ログインを処理する
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  // パスワードを比較する

  // JWTトークンを作成する
  const token = jwt.sign({ userId: "hoge" }, "secret");

  // JWTトークンをクライアントに送信する
  res.cookie("token", token, { httpOnly: true });
  res.redirect("/dashboard");
});

app.get("/dashboard", (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.redirect("/login");
  }

  jwt.verify(token, "secret", (err, decoded) => {
    console.log(decoded);
  });

  res.render("dashboard");
});

app.listen(port, () => {
  console.log(`auth app listening on port ${port}`);
});

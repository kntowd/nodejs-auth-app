const express = require("express");
const jwt = require("jsonwebtoken");
const port = 3000;

const app = express();

app.set("view engine", "ejs");

app.use(express.json());

// ログインページを表示する
app.get("/login", (req, res) => {
  res.render("login");
});

// 新規登録ページを表示する
app.get("/register", (req, res) => {
  res.render("register");
});

// 新規登録を処理する
app.post("/register", (req, res) => {
  const { name, email, password } = req.body;

  // JWTトークンを作成する
  const token = jwt.sign({ userId: newUser._id }, "secret");

  // JWTトークンをクライアントに送信する
  res.cookie("token", token, { httpOnly: true });
  res.redirect("/dashboard");
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});

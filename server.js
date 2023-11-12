const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

// ミドルウェアの設定
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'your-secret-key',
  resave: true,
  saveUninitialized: true
}));

// ダミーのユーザーデータ（本番環境ではデータベースを使用する）
const users = [];

// サインアップの処理
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;

  // パスワードのハッシュ化
  const hashedPassword = await bcrypt.hash(password, 10);

  // ユーザーデータを保存（本番環境ではデータベースに保存）
  users.push({ username, password: hashedPassword });

  res.status(200).send('Sign up successful');
});

// ログインの処理
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // ユーザーの存在を確認
  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).send('Invalid username or password');
  }

  // パスワードの検証
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(401).send('Invalid username or password');
  }

  // セッションにユーザー情報を保存
  req.session.user = { username };

  res.status(200).send('Login successful');
});

// ログアウトの処理
app.post('/logout', (req, res) => {
  // セッションを破棄
  req.session.destroy(err => {
    if (err) {
      return res.status(500).send('Internal Server Error');
    }
    res.status(200).send('Logout successful');
  });
});

// ログイン状態の確認
app.get('/checkLogin', (req, res) => {
  // セッションにユーザー情報があればログイン済みとみなす
  const isLoggedIn = !!req.session.user;
  res.status(200).json({ isLoggedIn });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

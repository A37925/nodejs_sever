const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const port = 3000;
const secretKey = 'key'; // Key bí mật để mã hóa và giải mã token

app.use(bodyParser.json());

// Danh sách người dùng giả định
const users = [
  { id: 1, name: 'Huy1', email: 'nguyen7quoc4huy02@gmail.com', password: bcrypt.hashSync('password1', 8) },
  { id: 2, name: 'Huy2', email: 'nguyenquochuy@gmail.com', password: bcrypt.hashSync('password2', 8) }
];

// Middleware để xác thực token
const verifyToken = (req, res, next) => {
  const token = req.headers['x-access-token'];
  if (!token) {
    return res.status(403).json({ error: 'Không có token' });
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(500).json({ error: 'Token không hợp lệ' });
    }
    req.userId = decoded.id;
    next();
  });
};

// Endpoint GET /
app.get('/', (req, res) => {
  res.send('Welcome to the Node.js Test API');
});

// Endpoint GET /users (cần xác thực)
app.get('/users', verifyToken, (req, res) => {
  res.json(users);
});

// Endpoint POST /users (cần xác thực)
app.post('/users', verifyToken, (req, res) => {
  const { id, name, email, password } = req.body;

  // Kiểm tra thông tin người dùng
  if (!id || !name || !email || !password) {
    return res.status(400).json({ error: 'Dữ liệu không hợp lệ' });
  }

  // Kiểm tra xem người dùng đã tồn tại hay chưa
  const userExists = users.some(user => user.id === id || user.email === email);
  if (userExists) {
    return res.status(400).json({ error: 'Người dùng đã tồn tại' });
  }

  // Mã hóa mật khẩu và thêm người dùng mới vào danh sách
  const hashedPassword = bcrypt.hashSync(password, 8);
  users.push({ id, name, email, password: hashedPassword });
  res.status(201).json({ message: 'Người dùng đã được thêm', user: { id, name, email } });
});

// Endpoint POST /login để lấy token
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Kiểm tra thông tin người dùng
  const user = users.find(user => user.email === email);
  if (!user) {
    return res.status(404).json({ error: 'Người dùng không tồn tại' });
  }

  // Kiểm tra mật khẩu
  const passwordIsValid = bcrypt.compareSync(password, user.password);
  if (!passwordIsValid) {
    return res.status(401).json({ error: 'Mật khẩu không chính xác' });
  }

  // Tạo token
  const token = jwt.sign({ id: user.id }, secretKey, { expiresIn: 86400 }); // Token hết hạn sau 24 giờ
  res.status(200).json({ auth: true, token });
});

// Xử lý lỗi 404
app.use((req, res) => {
  res.status(404).json({ error: 'Không tìm thấy dữ liệu' });
});

// Lắng nghe trên port 3000
app.listen(port, () => {
  console.log(`Server đang lắng nghe trên port ${port}`);
});

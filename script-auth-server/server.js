   require('dotenv').config();
   const express = require('express');
   const cors = require('cors');
   const jwt = require('jsonwebtoken');
   const bcrypt = require('bcrypt');

   const app = express();
   app.use(cors());
   app.use(express.json());

   // Временное хранилище пользователей (в реальном проекте используйте MongoDB)
   const users = [];

   // Регистрация
   app.post('/register', async (req, res) => {
     try {
       const { username, password } = req.body;
       
       // Проверка, существует ли пользователь
       if (users.find(u => u.username === username)) {
         return res.status(400).json({ success: false, error: 'User already exists' });
       }
       
       // Хеширование пароля
       const hashedPassword = await bcrypt.hash(password, 10);
       
       // Создание пользователя
       const user = {
         id: Date.now().toString(),
         username,
         password: hashedPassword,
         subscription: {
           active: false,
           expiresAt: null
         }
       };
       
       users.push(user);
       res.json({ success: true });
     } catch (error) {
       res.status(400).json({ success: false, error: error.message });
     }
   });

   // Авторизация
   app.post('/login', async (req, res) => {
     try {
       const { username, password } = req.body;
       const user = users.find(u => u.username === username);
       
       if (!user || !await bcrypt.compare(password, user.password)) {
         return res.status(401).json({ success: false, error: 'Invalid credentials' });
       }
       
       const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET || 'default_secret');
       res.json({ success: true, token });
     } catch (error) {
       res.status(400).json({ success: false, error: error.message });
     }
   });

   // Проверка подписки
   app.post('/validate', (req, res) => {
     try {
       const authHeader = req.headers.authorization;
       if (!authHeader || !authHeader.startsWith('Bearer ')) {
         return res.json({ valid: false });
       }
       
       const token = authHeader.split(' ')[1];
       const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default_secret');
       
       const user = users.find(u => u.id === decoded.userId);
       if (!user || !user.subscription.active) {
         return res.json({ valid: false });
       }
       
       res.json({ valid: true });
     } catch (error) {
       res.json({ valid: false });
     }
   });

   // Активация подписки (для тестирования)
   app.post('/activate', (req, res) => {
     try {
       const { username } = req.body;
       const user = users.find(u => u.username === username);
       
       if (!user) {
         return res.status(404).json({ success: false, error: 'User not found' });
       }
       
       user.subscription.active = true;
       user.subscription.expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // +30 дней
       
       res.json({ success: true });
     } catch (error) {
       res.status(400).json({ success: false, error: error.message });
     }
   });

   const PORT = process.env.PORT || 3000;
   app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
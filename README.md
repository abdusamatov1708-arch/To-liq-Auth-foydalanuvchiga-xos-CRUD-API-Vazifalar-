# To-liq-Auth-foydalanuvchiga-xos-CRUD-API-Vazifalar-
Ma'lumotlar bazasi sxemasi (schema.sql)
PostgreSQL da kerakli jadvallarni yaratish uchun quyidagi SQL buyruqlarini bajaring:

SQL
-- Foydalanuvchilar jadvali
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    parol_hash VARCHAR(255) NOT NULL
);

-- Vazifalar jadvali (user_id orqali bog'langan)
CREATE TABLE tasks (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    matn TEXT NOT NULL,
    bajarildi BOOLEAN DEFAULT FALSE
);
2. Loyihani sozlash va Kutubxonalar
Loyihani boshlash uchun kerakli paketlarni o'rnating:

Bash
npm init -y
npm install express pg bcrypt jsonwebtoken dotenv
3. Asosiy dastur kodi (server.js)
Quyidagi kod barcha talablarni (Auth, JWT, per-user CRUD, IDOR himoyasi, markazlashtirilgan xato middleware) o'z ichiga oladi:

JavaScript
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// PostgreSQL ulanish hovuzi (Pool)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:password@localhost:5432/todo_db'
});

const JWT_SECRET = process.env.JWT_SECRET || 'maxfiy_kalit_soz';

// ==========================================
// 1. AUTHENTICATION MIDDLEWARE
// ==========================================
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Autentifikatsiya tokeni talab qilinadi' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token yaroqsiz yoki muddati o\'tgan' });
    }
    // So'rov obyektiga foydalanuvchi ID sini biriktiramiz
    req.user = { id: user.id };
    next();
  });
};

// ==========================================
// 2. AUTH ROUTELARI (Register & Login)
// ==========================================

// Ro'yxatdan o'tish
app.post('/register', async (req, res, next) => {
  try {
    const { email, parol } = req.body;
    if (!email || !parol) {
      return res.status(400).json({ error: 'Email va parol kiritilishi shart' });
    }

    const saltRounds = 10;
    const parol_hash = await bcrypt.hash(parol, saltRounds);

    const result = await pool.query(
      'INSERT INTO users (email, parol_hash) VALUES ($1, $2) RETURNING id, email',
      [email, parol_hash]
    );

    res.status(201).json({
      message: 'Foydalanuvchi muvaffaqiyatli ro\'yxatdan o\'tdi',
      user: result.rows[0]
    });
  } catch (err) {
    if (err.code === '23505') { // PostgreSQL noyoblik (unique) xatosi
      return res.status(400).json({ error: 'Bu email allaqachon ro\'yxatdan o\'tgan' });
    }
    next(err);
  }
});

// Tizimga kirish
app.post('/login', async (req, res, next) => {
  try {
    const { email, parol } = req.body;
    if (!email || !parol) {
      return res.status(400).json({ error: 'Email va parol kiritilishi shart' });
    }

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ error: 'Email yoki parol noto\'g\'ri' });
    }

    const isMatch = await bcrypt.compare(parol, user.parol_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Email yoki parol noto\'g\'ri' });
    }

    // JWT token yaratish (1 soatga)
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1h' });

    res.json({
      message: 'Muvaffaqiyatli kirdingiz',
      token
    });
  } catch (err) {
    next(err);
  }
});

// ==========================================
// 3. VAZIFALAR (TASKS) CRUD ROUTELARI (Himoyalangan)
// ==========================================

// Barcha vazifalarni olish (Faqat o'zinikini)
app.get('/tasks', authMiddleware, async (req, res, next) => {
  try {
    const result = await pool.query(
      'SELECT id, matn, bajarildi FROM tasks WHERE user_id = $1 ORDER BY id DESC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    next(err);
  }
});

// Yangi vazifa qo'shish
app.post('/tasks', authMiddleware, async (req, res, next) => {
  try {
    const { matn } = req.body;
    if (!matn) {
      return res.status(400).json({ error: 'Vazifa matni bo\'sh bo\'lishi mumkin emas' });
    }

    const result = await pool.query(
      'INSERT INTO tasks (user_id, matn, bajarildi) VALUES ($1, $2, false) RETURNING id, matn, bajarildi',
      [req.user.id, matn]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    next(err);
  }
});

// Vazifani yangilash (IDOR oldini olish uchun user_id tekshiriladi)
app.put('/tasks/:id', authMiddleware, async (req, res, next) => {
  try {
    const { id } = req.params;
    const { matn, bajarildi } = req.body;

    // Parametrlashtirilgan so'rov va WHERE shartida user_id ni tekshirish IDOR ni to'xtatadi
    const result = await pool.query(
      `UPDATE tasks 
       SET matn = COALESCE($1, matn), bajarildi = COALESCE($2, bajarildi) 
       WHERE id = $3 AND user_id = $4 
       RETURNING id, matn, bajarildi`,
      [matn, bajarildi, id, req.user.id]
    );

    // rowCount orqali yozuv topilmaganligini yoki boshqa foydalanuvchiga tegishliligini tekshirish
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Vazifa topilmadi yoki unga kirish huquqingiz yo\'q' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    next(err);
  }
});

// Vazifani o'chirish
app.delete('/tasks/:id', authMiddleware, async (req, res, next) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM tasks WHERE id = $1 AND user_id = $2 RETURNING id',
      [id, req.user.id]
    );

    if (result.rowCount ===0) {
      return res.status(404).json({ error: 'Vazifa topilmadi yoki unga kirish huquqingiz yo\'q' });
    }

    res.json({ message: 'Vazifa muvaffaqiyatli o\'chirildi', id: result.rows[0].id });
  } catch (err) {
    next(err);
  }
});

// ==========================================
// 4. MARKAZLASHTIRILGAN XATOLARNI BOSHQARISH MIDDLEWARE
// ==========================================
app.use((err, req, res, next) => {
  console.error('Xatolik yuz berdi:', err.stack);
  res.status(500).json({
    error: 'Serverda ichki xatolik yuz berdi',
    details: err.message
  });
});

// Serverni ishga tushirish
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server ${PORT}-portda ishga tushdi`);
});
Xavfsizlik va Arxitektura Afzalliklari:
IDOR (Insecure Direct Object Reference) Himoyasi: Har bir PUT va DELETE so'rovida WHERE id = $X AND user_id = $Y sharti qo'llanilgani sababli, foydalanuvchi boshqa birovning ID raqamini bilgan taqdirda ham uning ma'lumotlarini o'zgartira yoki o'chira olmaydi.

Parametrlashtirilgan So'rovlar: SQL Injection hujumlarining oldini olish uchun $1, $2 kabi tayyor placeholder'lardan foydalanilgan.

Markazlashtirilgan Xato (Error) Middleware: Barcha marshrutlardagi xatolar next(err) orqali so'nggi middleware'ga uzatilib, bir xil JSON shaklida qaytariladi.

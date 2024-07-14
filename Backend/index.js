const express = require('express');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = "your-secret-key";

app.use(bodyParser.json());
app.use(cors());

// Register route
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  console.log("Register request body:", req.body);

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const saltRounds = 10; // Number of salt rounds for hashing
  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
      },
    });
    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: 'User already exists' });
  }
});

// Login route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  console.log("Login request body:", req.body); // Added logging

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ userId: user.id }, SECRET_KEY);
  res.status(200).json({ token });
});

// Middleware to authenticate JWT
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ error: 'Access denied' });
  try {
    const verified = jwt.verify(token, SECRET_KEY);
    req.user = verified;
    next();
  } catch (error) {
    res.status(400).json({ error: 'Invalid token' });
  }
};

// CRUD operations for todos
app.get('/todos', authenticateToken, async (req, res) => {
  const todos = await prisma.todo.findMany({ where: { userId: req.user.userId } });
  res.status(200).json(todos);
});

app.post('/todos', authenticateToken, async (req, res) => {
    const { title, content, startDate, endDate } = req.body;
    try {
      const todo = await prisma.todo.create({
        data: {
          title,
          content,
          startDate: new Date(startDate),
          endDate: new Date(endDate),
          userId: req.user.userId,
        },
      });
      res.status(201).json(todo);
    } catch (error) {
      console.error('Error adding todo:', error);
      res.status(500).json({ error: 'Failed to add todo' });
    }
  });
  
  app.put('/todos/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { title, content, startDate, endDate } = req.body;
    try {
      const todo = await prisma.todo.update({
        where: { id: Number(id) },
        data: { title, content, startDate: new Date(startDate), endDate: new Date(endDate) },
      });
      res.status(200).json(todo);
    } catch (error) {
      console.error('Error updating todo:', error);
      res.status(500).json({ error: 'Failed to update todo' });
    }
  });
app.delete('/todos/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    await prisma.todo.delete({ where: { id: Number(id) } });
    res.status(204).send();
  } catch (error) {
    res.status(400).json({ error: 'Todo not found' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

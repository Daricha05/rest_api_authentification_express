const express = require('express');
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const adminRoutes = require('./routes/admin');

const app = express();

app.use(express.json());

app.use('/', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/admin', adminRoutes);

module.exports = app;
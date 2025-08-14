const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const contactRoutes = require('./routes/contactRoutes');
const cors = require('cors');

dotenv.config();
const app = express();

app.use(cors());
app.use(express.json());

// Root route
app.get('/', (req, res) => {
  res.send("API is running");
});

// Contact form route
app.use('/api/contact', contactRoutes);

const authRoutes = require('./routes/authRoutes');
app.use('/api', authRoutes);

// 404 handler (for unknown routes)
app.use((req, res, next) => {
  console.warn(" 404 - Route not found:", req.originalUrl);
  res.status(404).json({ error: 'Route not found' });
});


// MongoDB connection and server start
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log(" MongoDB connected");
    app.listen(process.env.PORT, () => {
      console.log(` Server running on port ${process.env.PORT}`);
    });
  })
  .catch(err => console.error(" DB connection error:", err));
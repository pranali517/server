const express = require('express');
const router = express.Router();
const { signup, login, forgotPassword, resetPassword } = require('../controllers/authcontrollers');

router.post('/signup', signup);
router.post('/login', login);

// 🔐 New routes for password reset
router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPassword);

module.exports = router;
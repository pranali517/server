const User = require('../models/user');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

// Helper to generate a unique username
async function generateUniqueUsername(baseUsername) {
  let newUsername = baseUsername;
  let counter = 1;

  while (await User.findOne({ username: newUsername })) {
    newUsername = `${baseUsername}_${counter}`;
    counter++;
  }
  return newUsername;
}

// Smart signup (works for normal & Google signups)
const signup = async (req, res) => {
  const { username, email, password, isGoogle } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  try {
    let existingUser = await User.findOne({ email });

    if (existingUser) {
      if (isGoogle) {
        return res.status(200).json({
          message: 'User already exists, logged in',
          username: existingUser.username
        });
      }
      return res.status(400).json({ error: 'Email already exists.' });
    }

    let finalUsername = username;
    let usernameTaken = await User.findOne({ username });

    if (usernameTaken) {
      if (isGoogle) {
        finalUsername = await generateUniqueUsername(username);
      } else {
        return res.status(400).json({ error: 'Username already exists.' });
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username: finalUsername, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'Signup successful!', username: newUser.username });

  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ error: 'Server error during signup.' });
  }
};

// Normal login
const login = async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ error: 'User not found.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Incorrect password.' });
    }

    res.status(200).json({ message: 'Login successful!', username: user.username });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: 'Server error during login.' });
  }
};

// 🔐 Forgot Password
const forgotPassword = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found.' });

    const token = crypto.randomBytes(32).toString('hex');
    user.resetToken = token;
    user.resetTokenExpiry = Date.now() + 1000 * 60 * 30; // 30 minutes
    await user.save();

    const resetLink = `http://localhost:3000/reset-password?token=${token}`;

    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    await transporter.sendMail({
      to: user.email,
      subject: 'Password Reset',
      html: `<p>Click <a href="${resetLink}">here</a> to reset your password.</p>`,
    });
console.log("Sending reset email to:", user.email);
console.log("Reset link:", resetLink);
    res.json({ message: 'Reset link sent to your email.' });
  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ message: 'Server error during password reset request.' });
  }
};

// 🔐 Reset Password
const resetPassword = async (req, res) => {
  const { token, newPassword } = req.body;
  try {
    const user = await User.findOne({
      resetToken: token,
      resetTokenExpiry: { $gt: Date.now() },
    });

    if (!user) return res.status(400).json({ message: 'Invalid or expired token.' });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    res.json({ message: 'Password reset successful.' });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ message: 'Server error during password reset.' });
  }
};

module.exports = { signup, login, forgotPassword, resetPassword };
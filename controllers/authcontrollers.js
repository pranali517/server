const User = require('../models/user');
const bcrypt = require('bcryptjs');

// Helper to generate a unique username
async function generateUniqueUsername(baseUsername) {
  let newUsername = baseUsername;
  let counter = 1;

  while (await User.findOne({ username: newUsername })) {
    newUsername = ${baseUsername}_${counter};
    counter++;
  }
  return newUsername;
}
// Smart signup (works for normal & Google signups)
const signup = async (req, res) => {
  const { username, email, password, isGoogle } = req.body; 

  // isGoogle should be sent from frontend for Google login 


  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  try {
    // Check if email exists first
    let existingUser = await User.findOne({ email });

    if (existingUser) {
      // If Google signup and email exists → log them in
      if (isGoogle) {
        return res.status(200).json({
          message: 'User already exists, logged in',
          username: existingUser.username
        });
      }
      return res.status(400).json({ error: 'Email already exists.' });
    }

    let finalUsername = username;

    // Check if username is taken
    let usernameTaken = await User.findOne({ username });
    if (usernameTaken) {
      if (isGoogle) {
        // Auto-generate a new username for Google users
        finalUsername = await generateUniqueUsername(username);
      } else {
        return res.status(400).json({ error: 'Username already exists.' });
      }
    }

    // For new user → hash password and save
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

module.exports = { signup, login };
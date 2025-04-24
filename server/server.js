const express = require('express');
const cors = require('cors');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors()); 
app.use(express.json());

// Example route
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  // Replace this with real authentication logic
  if (username === 'admin' && password === 'admin') {
    return res.json({
      token: 'fake-jwt-token',
      user: {
        username: 'admin',
        role: 'admin'
      }
    });
  }

  res.status(401).send('Invalid credentials');
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
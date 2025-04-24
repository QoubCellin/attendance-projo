const db = require('./db');
const bcrypt = require('bcrypt');

module.exports = {
  async findByUsername(username) {
    const [rows] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
    return rows[0];
  },
  // Add other user-related database operations
};
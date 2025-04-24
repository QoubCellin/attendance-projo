const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('../models/db');

module.exports = {
    async login(req, res) {
        try {
            const { username, password } = req.body;
            
            // Find user
            const [users] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
            if (users.length === 0) {
                return res.status(401).json({ message: 'Invalid username or password' });
            }
            
            const user = users[0];
            
            // Verify password
            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                return res.status(401).json({ message: 'Invalid username or password' });
            }
            
            
            // Create token
            const token = jwt.sign(
                { userId: user.user_id, role: user.role },
                process.env.JWT_SECRET,
                { expiresIn: '1d' }
            );
            
            // Send response
            res.json({
                token,
                user: {
                    user_id: user.user_id,
                    username: user.username,
                    email: user.email,
                    role: user.role,
                    full_name: user.full_name
                }
            });
            
        } catch (err) {
            console.error('Login error:', err);
            res.status(500).json({ message: 'Server error during login' });
        }
    }
};
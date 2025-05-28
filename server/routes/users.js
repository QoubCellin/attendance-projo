const express = require('express');
const {
	signup,
	signin,
	verifyOTP,
	authenticate,
	checkAdmission,
} = require('../controllers/users');
const router = express.Router();

router.post('/register', signup);
router.post('/login', signin);
router.post('/verify_otp', verifyOTP);
router.get('/profile', authenticate, (req, res) => {
	res.json(req.user);
});
router.get('/user/check-admission/:admission_number', checkAdmission);

module.exports = router;

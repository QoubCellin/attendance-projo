const User = require('../models/users');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { SECRET_KEY, ACCESS_TOKEN_EXPIRY, EMAIL_ADDRESS, APP_PASSWORD } =
	process.env;
const bcrypt = require('bcrypt');

const transporter = nodemailer.createTransport({
	service: 'gmail',
	auth: {
		user: EMAIL_ADDRESS,
		pass: APP_PASSWORD,
	},
	port: 587,
	secure: false,
});

const generateToken = (payload) => {
	const accessToken = jwt.sign(payload, SECRET_KEY, {
		expiresIn: ACCESS_TOKEN_EXPIRY,
		algorithm: 'HS256',
	});

	const refreshToken = jwt.sign(payload, SECRET_KEY, {
		expiresIn: '7d', // Set the refresh token expiry time (e.g., 7 days)
		algorithm: 'HS256',
	});

	return { accessToken, refreshToken };
};

// generate otp

const generateOTP = () => {
	const min = 100000;
	const max = 999999;
	return Math.floor(Math.random() * (max - min + 1)) + min;
};

const signup = async (req, res) => {
	const { admission_number, password, email } = req.body;
	if (!admission_number || !password || !email) {
		return res.status(400).json({ message: 'All fields are required' });
	}

	try {
		await User.create({
			email,
			password,
			admission_number,
		});

		res.status(201).json({ message: 'User registered successfully' });
	} catch (error) {
		res.status(500).json({ message: error.message });
	}
};

const signin = async (req, res) => {
	const { password, admission_number } = req.body;
	if (!admission_number || !password) {
		return res.status(400).json({ message: 'All fields are required' });
	}

	try {
		const { email } = await User.findOne({ admission_number });
		await User.login(admission_number, password);

		const generatedOTP = generateOTP();

		const salt = await bcrypt.genSalt(10);
		const hashedOTP = await bcrypt.hash(String(generatedOTP), salt);
		await User.findOneAndUpdate({ email }, { otp: hashedOTP });

		const mailOptions = {
			from: EMAIL_ADDRESS,
			to: email,
			subject: 'Attendance System - OTP Verification', // Subject line
			text: `Your One-Time Password (OTP) is: ${generatedOTP}`, // plain text body
		};

		await transporter.sendMail(mailOptions);

		res.status(200).json({
			message: 'verify OTP sent to email',
			generatedOTP,
		});
	} catch (error) {
		console.log('error:', error.message);
		res.status(401).json({ message: error.message });
	}
};

const verifyOTP = async (req, res) => {
	const { otp, admission_number } = req.body;
	console.log(otp, admission_number);

	try {
		const user = await User.findOne({ admission_number });

		const { accessToken } = generateToken({
			admission_number: user.admission_number,
			email: user.email,
			id: user.id,
			name: user.name,
		});

		const dbOTP = bcrypt.compareSync(otp, user.otp);

		if (!dbOTP) return res.status(401).json({ message: 'Invalid OTP' });

		await User.findOneAndUpdate({ admission_number }, { otp: null });

		res.status(200).json({
			message: 'Authenticated successfully',
			accessToken,
		});
	} catch (error) {
		console.log('Error:', error.message);
		res.status(500).json({ error: error.message });
	}
};

const authenticate = (req, res, next) => {
	const authHeader = req.headers['authorization'];
	const token = authHeader && authHeader.split(' ')[1];

	if (!token) {
		return res.status(401).json({ message: 'No token provided' });
	}

	jwt.verify(token, SECRET_KEY, (err, user) => {
		if (err) {
			console.log(err.message);
			return res.status(403).json({ message: 'Invalid token' });
		}

		req.user = user;
		next();
	});
};

const signout = (req, res) => {
	req.session.destroy();

	res.clearCookie('token');
	res.status(200).json({ message: 'Logged out successfully' });
};

// Add this route to your users.js routes file
const checkAdmission = async (req, res) => {
	try {
		const { admissionNumber } = req.params;

		// Find user by admission number
		const user = await User.findOne({ admissionNumber });

		if (!user) {
			return res.status(404).json({ message: 'User not found' });
		}

		return res.status(200).json({
			id: user._id,
			admission_number: user.admission_number,
			role: user.role,
			email: user.email,
		});
	} catch (error) {
		console.error('Error checking admission number:', error);
		return res.status(500).json({ message: 'Server error' });
	}
};

module.exports = {
	signup,
	signin,
	verifyOTP,
	signout,
	authenticate,
	checkAdmission,
};

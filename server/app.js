const express = require('express');
require('dotenv').config();
const cors = require('cors');
const logger = require('morgan');
const helmet = require('helmet');

const app = express();

app.use(
	cors({
		origin: (origin, callback) => {
			const allowedOrigins = ['http://127.0.0.1:5500'];
			if (!origin || allowedOrigins.includes(origin)) {
				callback(null, true);
			} else {
				callback(new Error('Not allowed by CORS'));
			}
		},
		credentials: true,
	})
);

// Security measures
app.use(
	helmet({
		contentSecurityPolicy: {
			directives: {
				defaultSrc: ["'self'"],
				objectSrc: ["'none'"],
			},
		},
		frameguard: { action: 'deny' }, // Prevent Clickjacking
		referrerPolicy: { policy: 'strict-origin-when-cross-origin' }, // Control Referrer Header
		xssFilter: true, // Prevent XSS Attacks
		dnsPrefetchControl: { allow: false }, // Prevent DNS Prefetching
	})
);

const userRoutes = require('./routes/users');
const attendanceRoutes = require('./routes/attendance');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/api/auth', userRoutes);
app.use('/api/attendance', attendanceRoutes);
module.exports = app;

require('dotenv').config();
const mongoose = require('mongoose');
const express = require('express');
const bodyParser = require('body-parser');
// const cookieParser = require('cookie-parser');
// const csrf = require('csurf');
// const cors = require('cors');
// const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const Student = require('./models/users');
// const { generatePDF, convertToCSV } = require('./utils/reportGenerator');
const { API_PORT, MONGO_URI, EMAIL_ADDRESS, APP_PASSWORD } = process.env;

const app = require('./app');

// Middleware
// app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.json());

const connection = async () => {
  try {
    await mongoose.connect(MONGO_URI);
    console.log('✅ MongoDB connected successfully');

    app.listen(API_PORT, () => {
      console.log(`🚀 Server running on port ${API_PORT}`);
    });
  } catch (error) {
    console.error('❌ MongoDB connection error:', error);
    process.exit(1);
  }
};
connection();

// // Email Transporter
// const transporter = nodemailer.createTransport({
//   service: 'gmail',
//   auth: {
//     user: EMAIL_ADDRESS,
//     pass: APP_PASSWORD,
//   },
// });

// // Verify transporter connection
// transporter.verify((error) => {
//   if (error) console.error('❌ Email transporter error:', error);
//   else console.log('📧 Email transporter ready');
// });

// // Routes
// app.get('/api/csrf-token', (req, res) => {
//   res.json({ csrfToken: req.csrfToken() });
// });

// // Auth Routes
// app.post('/api/auth/login', async (req, res) => {
//   try {
//     const { admission_number, password } = req.body;

//     const student = await Student.findOne({ admission_number });
//     if (!student || !(await bcrypt.compare(password, student.password))) {
//       return res.status(401).json({ message: 'Invalid credentials' });
//     }

//     const otp = Math.floor(100000 + Math.random() * 900000).toString();

//     await transporter.sendMail({
//       from: process.env.EMAIL_FROM,
//       to: student.email,
//       subject: 'Your OTP Code',
//       text: `Your OTP code is: ${otp}`,
//     });

//     student.otp = {
//       code: await bcrypt.hash(otp, 10),
//       expires: Date.now() + 5 * 60 * 1000, // 5 minutes
//     };

//     await student.save();

//     res.json({ requiresOTP: true });
//   } catch (error) {
//     console.error('Login error:', error);
//     res.status(500).json({ message: 'Server error during login' });
//   }
// });

// app.post('/api/auth/verify-otp', async (req, res) => {
//   try {
//     const { otp, admission_number } = req.body;
//     const student = await Student.findOne({ admission_number });

//     if (!student || !student.otp) {
//       return res.status(400).json({ message: 'Invalid request' });
//     }

//     if (Date.now() > student.otp.expires) {
//       return res.status(400).json({ message: 'OTP expired' });
//     }

//     const isValid = await bcrypt.compare(otp, student.otp.code);
//     if (!isValid) {
//       return res.status(400).json({ message: 'Invalid OTP' });
//     }

//     const sessionToken = uuidv4();
//     student.sessions.push(sessionToken);
//     student.otp = undefined;

//     await student.save();

//     res.json({ token: sessionToken });
//   } catch (error) {
//     console.error('OTP verification error:', error);
//     res.status(500).json({ message: 'Server error during OTP verification' });
//   }
// });

// Get Students (filtered)
// app.get('/api/students', async (req, res) => {
//   try {
//     const { course, status, year } = req.query;
//     const filter = {};
//     if (course) filter.course = course;
//     if (status) filter.status = status;
//     if (year) filter.enrollment_year = parseInt(year);

//     const students = await Student.find(filter).select(
//       '-password -sessions -otp'
//     );
//     res.json(students);
//   } catch (error) {
//     console.error('Fetch students error:', error);
//     res.status(500).json({ message: 'Server error fetching students' });
//   }
// });

// // Report Generation
// app.post('/api/reports', async (req, res) => {
//   try {
//     const { reportType, format, filters } = req.body;
//     const students = await Student.find(filters);

//     if (format === 'csv') {
//       const csv = convertToCSV(students);
//       res.header('Content-Type', 'text/csv');
//       res.attachment('report.csv');
//       return res.send(csv);
//     }

//     const pdf = await generatePDF(students);
//     res.header('Content-Type', 'application/pdf');
//     res.attachment('report.pdf');
//     return res.send(pdf);
//   } catch (error) {
//     console.error('Report generation error:', error);
//     res.status(500).json({ message: 'Report generation failed' });
//   }
// });

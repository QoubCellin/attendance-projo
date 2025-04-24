const { Router } = require('express');
const { markAttendance } = require('../controllers/attendance');
const router = new Router();

router.post('/mark-attendance', markAttendance);

module.exports = router;

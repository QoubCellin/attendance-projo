const { Router } = require('express');
const { markAttendance, viewAttendance } = require('../controllers/attendance');
const router = new Router();

router.post('/mark-attendance', markAttendance);
router.get('/all', viewAttendance);

module.exports = router;

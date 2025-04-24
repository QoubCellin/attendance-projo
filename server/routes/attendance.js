const { Router } = require('express');
const { markAttendance } = require('../controllers/attendance');
const router = new Router();

router.post('/mark', markAttendance);

module.exports = router;

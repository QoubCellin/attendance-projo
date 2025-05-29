const Attendance = require('../models/attendance');

const markAttendance = async (req, res) => {
  try {
    const { studentId, classId, status, date } = req.body;

    // Validate input
    if (!studentId || !classId || !status || !date) {
      return res.status(400).json({
        message: 'All fields (studentId, classId, status, date) are required',
      });
    }

    // Validate status
    const validStatuses = ['present', 'late', 'excused'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        message: 'Invalid status. Must be one of: present, late, excused',
      });
    }

    // Validate date (cannot mark attendance for future dates)
    const selectedDate = new Date(date);
    const today = new Date();
    today.setHours(0, 0, 0, 0); // Reset time for comparison
    selectedDate.setHours(0, 0, 0, 0);
    if (selectedDate > today) {
      return res
        .status(400)
        .json({ message: 'Cannot mark attendance for a future date' });
    }

    // Check if attendance has already been marked for this date and class
    let attendance = await Attendance.findOne({
      classId,
      date: selectedDate,
    });
    if (attendance) {
      const existingRecord = attendance.records.find(
        (record) => record.studentId.toString() === studentId
      );
      if (existingRecord) {
        return res.status(400).json({
          message: 'Attendance already marked for this date',
        });
      }
      // Add new record to existing attendance
      attendance.records.push({ studentId, status });
      await attendance.save();
    } else {
      // Create new attendance record
      attendance = new Attendance({
        classId,
        date: selectedDate,
        records: [{ studentId, status }],
      });
      await attendance.save();
    }

    res.status(201).json({ message: 'Attendance marked successfully' });
  } catch (error) {
    console.error('Error marking attendance:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

const viewAttendance = async (req, res) => {
  try {
    const attendance = await Attendance.find().populate(
      'records.studentId',
      'name admission_number email'
    ); // populate name and other fields if needed

    console.log('Attendance records:', attendance);
    res.json({ attendance });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

module.exports = { markAttendance, viewAttendance };

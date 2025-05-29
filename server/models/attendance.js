const mongoose = require('mongoose');

const attendanceSchema = new mongoose.Schema({
  classId: {
    type: String,
    required: true,
  },
  date: { type: Date, required: true },
  records: [
    {
      studentId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Student',
        required: true,
      },
      status: {
        type: String,
        enum: ['present', 'excused'],
        required: true,
      },
    },
  ],
});

module.exports = mongoose.model('Attendance', attendanceSchema);

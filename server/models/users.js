const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const studentSchema = new mongoose.Schema(
  {
    admission_number: { type: String, required: true, unique: true },
    // full_name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    // course: { type: String, required: true },
    // enrollment_year: { type: Number, required: true },
    // status: { type: String, enum: ['active', 'graduated', 'suspended'], default: 'active' },
    password: { type: String, required: true },
    otp: {
      type: String,
    },
    sessions: [String],
  },
  { timestamps: true }
);

// Hash password before saving
studentSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

studentSchema.statics.login = async function (admission_number, password) {
  const student = await this.findOne({ admission_number });
  if (!student) throw new Error('Invalid admission number or password');

  const isMatch = await bcrypt.compare(password, student.password);
  if (!isMatch) throw new Error('Invalid admission number or password');

  return student;
};

module.exports = mongoose.model('Student', studentSchema);

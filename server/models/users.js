const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const studentSchema = new mongoose.Schema({
    admission_number: { type: String, required: true, unique: true },
    full_name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    course: { type: String, required: true },
    enrollment_year: { type: Number, required: true },
    status: { type: String, enum: ['active', 'graduated', 'suspended'], default: 'active' },
    password: { type: String, required: true },
    otp: {
        code: { type: String },
        expires: { type: Number }
    },
    sessions: [String]
}, { timestamps: true });

// Hash password before saving
studentSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 10);
    next();
});

module.exports = mongoose.model('Student', studentSchema);

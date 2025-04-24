const { Schema, model } = require('mongoose');
const bcrypt = require('bcrypt');

const UserSchema = new Schema({
	admission_number: {
		type: String,
		unique: true,
	},
	email: {
		type: String,
		unique: true,
	},
	otp: {
		type: String,
		default: null,
	},
	user_role: {
		type: String,
		enum: ['student', 'lecturer', 'admin'],
		default: 'student',
	},
	password: {
		type: String,
		required: true,
	},
});

// Hash the password before saving
UserSchema.pre('save', async function (next) {
	if (!this.isModified('password')) return next();

	const salt = await bcrypt.genSalt(10);
	this.password = await bcrypt.hash(this.password, salt);
	next();
});

UserSchema.statics.login = async function (admission_number, password) {
	try {
		const user = await this.findOne({ admission_number });

		if (user && bcrypt.compareSync(password, user.password)) {
			return user;
		}
		throw new Error('Incorrect credentials');
	} catch (error) {
		throw error;
	}
};

module.exports = model('User', UserSchema);

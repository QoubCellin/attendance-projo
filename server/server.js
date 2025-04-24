const app = require('./app');
const { connect } = require('mongoose');
const { API_PORT, MONGO_URI } = process.env;
const port = process.env.PORT || API_PORT;

const connection = async () => {
	try {
		await connect(MONGO_URI);
		console.log(`DB connection successful`);

		app.listen(port, () =>
			console.log(`Listening for requests on port ${port}`)
		);
	} catch (error) {
		console.log(error.message);
	}
};

connection();

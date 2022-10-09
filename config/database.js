const mongoose = require('mongoose');

const { MONGODB_URL } = process.env;

exports.connect = () => {
  mongoose
    .connect(MONGODB_URL, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    })
    .then(() => console.log('DB CONNECTED'))
    .catch((err) => {
      console.log('DB CONNECTION FAILED');
      console.log(err);
      process.exit(1);
    });
};

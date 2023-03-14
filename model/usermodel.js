const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  fullName: { type: String, required: true },
  mobileNumber: { type: String, required: true }
});

module.exports = mongoose.model('User', userSchema);
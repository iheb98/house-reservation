const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const UserSchema = mongoose.Schema({
    lastName: {
        type: String
    },
    firstName: {
        type: String
    },
    email: {
        type: String,
    },
    address: {
        type: String
    },
    phone: {
        type: String
    },
    username: {
        type: String
    },
    password: {
        type: String
    },
    profileImage: {
        type: String,
        default: "https://www.clipartkey.com/mpngs/m/152-1520367_user-profile-default-image-png-clipart-png-download.png"
    }
});

module.exports = mongoose.model('users', UserSchema);

module.exports.comparePassword = function (candidatePassword, hash, callback) {
    bcrypt.compare(candidatePassword, hash, (err, isMatch) => {
        if (err) throw err;
        callback(null, isMatch);
    })
}
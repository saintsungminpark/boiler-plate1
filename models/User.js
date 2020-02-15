const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const saltRounds = 10
const jwt = require('jsonwebtoken')

const userSchema = mongoose.Schema({
    name: {
        type: String,
        maxlength: 50
    },
    email: {
        type: String,
        trim: true,
        unique: 1
    },
    password: {
        type: String,
        minlength: 5
    },
    lastname: {
        type: String,
        maxlength: 50
    },
    role: {
        type: Number,
        default: 0
    },
    image: String,
    token: {
        type: String
    },
    tokenExp: { // Exp: Expiration 토큰 사용 유효기간
        type: Number
    }
})

userSchema.pre('save', function (next) {

    var user = this;

    if (user.isModified('password')) { // user.password가 바뀔떄만 함수 실행

        //비밀번호 암호화 시킨다
        bcrypt.genSalt(saltRounds, function (err, salt) {
            if (err) return next(err)
            bcrypt.hash(user.password, salt, function (err, hash) {
                if (err) return next(err)
                user.password = hash
                next()
            });
        });
    } else {
        next()
    }

})

userSchema.methods.comparePassword = function (plainPassword, callback) {

    //plainPassword 12345 암호화된 비밀번호 $2b$10$.... 이 같은지 체크
    bcrypt.compare(plainPassword, this.password, function (err, isMatch) {
        if (err) return callback(err);
        callback(null, isMatch);
    })
}

userSchema.methods.generateToken = function (callback) {

    var user = this;

    //jsonwebToken을 이용해서 token을 생성하기
    var token = jwt.sign(user._id.toHexString(), 'secretToken')

    user.token = token
    user.save(function (err, user) {
        if (err) return callback(err)
        callback(null, user)
    })

}

const User = mongoose.model('User', userSchema)

module.exports = { User }
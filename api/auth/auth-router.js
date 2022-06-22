const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require('../users/users-model')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

router.post("/register", validateRoleName, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  const { username, password } = req.body
  const role_name = req.role_name
  const hash = bcrypt.hashSync(password, 12)
  const user = { username, role_name, password: hash }
  const newUser = await Users.add(user)

  res.status(201).json({
    user_id: newUser.user_id,
    username: newUser.username,
    role_name: newUser.role_name
  })
});
// add({ username, password, role_name })

const generateToken = user => {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role: user.role_id,
    role_name: user.role_name
  }
  const options = {
    expiresIn: '1d'
  }
  return jwt.sign(payload, JWT_SECRET, options)
}

router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  const user = req.user
  const { password } = req.body

  const validCreds = bcrypt.compareSync(password, user.password)

  if (validCreds) {
    res.status(200).json({
      message: `${user.username} is back!`,
      token: generateToken(user)
    })
  } else {
    next({status: 401, message: 'invalid credentials'})
  }
});

module.exports = router;

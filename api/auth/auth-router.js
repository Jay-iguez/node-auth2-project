const router = require("express").Router();
const Users_model = require('../users/users-model')
const bcrypt = require('bcryptjs')
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!

router.post("/register", validateRoleName, async (req, res, next) => {
  try {
    const {username, password, role_name} = req.body
    const hash = bcrypt.hashSync(password, 12)
    const payload = {username: username, password: hash, role_name: role_name}
    const new_user = await Users_model.add(payload)

    res.status(201).json(new_user)
  } catch(err) {
    next({status: 500, message: 'Error in registering new user: ' + err.message})
  }
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
});


router.post("/login", checkUsernameExists, async (req, res, next) => {
  const {username, password} = req.body

  const [user] = await Users_model.findBy({username: username})

  if (bcrypt.compareSync(password, user.password)){
      const token = Users_model.create_token(user, JWT_SECRET)
      res.status(200).json({
        message: user.username + " is back!",
        token: token
      })
  } else {
    next({status: 401, message: "invalid credentials"})
  }


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
});

module.exports = router;

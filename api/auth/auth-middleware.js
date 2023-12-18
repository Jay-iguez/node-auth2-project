const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require('jsonwebtoken')
const Users_model = require('../users/users-model')

const restricted = (req, res, next) => {
  const token = req.headers.authorization

  if (token) {
    jwt.verify(token, JWT_SECRET, (err, decoded_jwt) => {
      if(err) {
        next({status: 401, message: "Token invalid"})
      } else {
        req.valid_jwt = decoded_jwt
        next()
      }
    })
  } else {
    next({status: 401, message: 'Token required'})
  }
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
}

const only = role_name => (req, res, next) => {
  const token = req.valid_jwt

  if (token && token.role_name === role_name){
    next()
  } else {
    next({status: 403, message: 'This is not for you'})
  }
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
}


const checkUsernameExists = (req, res, next) => {
  const {username} = req.body

  Users_model.findBy({username: username})
    .then(user => {
      const [destructured_user] = user

      if (destructured_user) {
        next()
      } else {
        next({status: 401, message: "Invalid credentials"})
      }
    })
    .catch(err => {
      next({status: 500, message: 'Error in finding user by: ' + username + " --- " + err.message})
    })
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
}


const validateRoleName = (req, res, next) => {
  const {role_name} = req.body

  if(role_name === undefined){
    req.body.role_name = 'student'
    next()
  }


  const trimmed_role_name = role_name !== undefined ? role_name.trim() : ""

  if (trimmed_role_name === "") {
    req.body.role_name = "student"
  } else if (trimmed_role_name === 'admin'){
    next({status: 422, message: "Role name can not be admin"})
  } else if (trimmed_role_name.length > 32) {
    next({status: 422, message: "Role name can not be longer than 32 chars"})
  } else {
    req.body.role_name = trimmed_role_name
    next()
  }
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}

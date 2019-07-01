const express = require("express");
const passportRouter = express.Router();
const bcrypt = require("bcrypt");
const bcryptSalt = 10;
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const ensureLogin = require("connect-ensure-login");

// Require user model
const User = require("../models/user");

// Add bcrypt to encrypt passwords

// Add passport

// const ensureLogin = require("connect-ensure-login");

// pass

passportRouter.get("/signup", (req, res, next) => {
  res.render("passport/signup.hbs");
});

passportRouter.post("/new-user", (req, res, next) => {
	const username = req.body.username;
	const password = req.body.password;

	if (username === "" || password === "") {
		res.render("/signup", {
			"message": "Indicate username and password",
			"section": "signup"
		});
		return;
	}

	User.findOne({
		username
	})
		.then(user => {
			if (user !== null) {
				res.render("/signup", {
					"message": "The username already exists",
					"section": "signup"
				});
				return;
			}

			const salt = bcrypt.genSaltSync(bcryptSalt);
			const hashPass = bcrypt.hashSync(password, salt);

			const newUser = new User({
				username,
				password: hashPass
			});

			newUser.save((err) => {
				if (err) {
					res.render("/signup", {
						message: "Something went wrong",
						"section": "signup"
					});
				} else {
					res.redirect("/login");
				}
			});
		})
		.catch(error => {
			next(error)
		})
});

passportRouter.get(
  "/private-page",
  ensureLogin.ensureLoggedIn(),
  (req, res) => {
    res.render("passport/private", { user: req.user });
  }
);

passportRouter.get("/login", (req, res, next) => {
  res.render("passport/login.hbs");
});



passportRouter.post("/login-user", passport.authenticate("local", {
    successReturnToOrRedirect: "/private-page",
    failureRedirect: "/login",
    failureFlash: true,
    passReqToCallback: true
  }));

module.exports = passportRouter;
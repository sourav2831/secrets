require("dotenv").config()
const express = require("express")
const bodyParser = require("body-parser")
const mongoose = require("mongoose")
const session = require("express-session")
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose")
const GoogleStrategy = require("passport-google-oauth20").Strategy
const findOrCreate=require("mongoose-findorcreate")
// const encrypt=require("mongoose-encryption") // level 2 authentication
// const md5 =require("md5") //level 3 authentication hashing
// const bcrypt = require("bcrypt") //level 4 authentication hashing salting

// const saltRounds=10
const app = express()
app.set("view engine", "ejs")
app.use(express.static("public"))
app.use(bodyParser.urlencoded({ extended: true }))
app.use(session({
    secret: "Our little secret",
    resave: false,
    saveUninitialized:false
}))
app.use(passport.initialize())
app.use(passport.session())

mongoose.connect("mongodb://localhost:27017/userDB", { useUnifiedTopology: true, useNewUrlParser: true })
mongoose.set('useCreateIndex', true);
// const userSchema = new mongoose.Schema({
//     email: String,
//     password:String
// })

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
})
userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate)
//userSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields:["password"]})
const User = mongoose.model("User", userSchema)
passport.use(User.createStrategy())

// passport.serializeUser(User.serializeUser())
// passport.deserializeUser(User.deserializeUser())  //For Local
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
    function (accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", (req, res) => {
    res.render("home")
})

app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile"] })
)

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
    });
  
app.get("/login", (req, res) => {
    res.render("login")
})

app.get("/register", (req, res) => {
    res.render("register")
})

app.get("/secrets", (req, res) => {
    if (req.isAuthenticated()) {
        User.find({ "secret": { $ne: null } }, (err, foundUsers) => {
            if (err) {
                console.log(err);
            }
            else {
                if (foundUsers) {
                    res.render("secrets", { usersWithSecrets: foundUsers })
                }
            }
        })
        
    }
    else {
        res.redirect("/login")
    }
})

app.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit")
    }
    else {
        res.redirect("/login")
    }
})

app.get("/logout", (req, res) => {
    req.logout()
    res.redirect("/")
})

app.post("/register", (req, res) => {
    User.register({ username: req.body.username }, req.body.password, (err, user) => {
        if (err) {
            console.log(err);
            res.redirect("/register")
        }
        else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets")
            })
        }
    })
    // bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
    //     if (err) {
    //         console.log(err);
    //     }
    //     else {
    //         const user = new User({
    //             email: req.body.username,
    //             password: hash                       //md5(req.body.password) //level 3
    //         })
    //         user.save((err) => {
    //             if (err) {
    //                 console.log(err)
    //             }
    //             else {
    //                 res.render("secrets")
    //             }
    //         })
    //     }
    // })
})

app.post("/login", (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    })
    req.login(user, (err) => {
        if (err) {
            console.log(err);
        }
        else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets")
            })
        }
    })
    // const username = req.body.username
    // const password = req.body.password                       //md5(req.body.password) //level 3
    // User.findOne({ email: username }, (err, foundUser) => {
    //     if (err) {
    //         console.log(err);
    //     }
    //     else {
    //         if (foundUser) {
    //             bcrypt.compare(password, foundUser.password, (err, result) => {
    //                 if (err) {
    //                     console.log(err);
    //                 }
    //                 else if (result) {
    //                     res.render("secrets")
    //                 }
    //                 else {
    //                     console.log("Wrong password");
    //                 }
    //             })
    //         }
    //         else {
    //             console.log("Please register first");
    //         }
    //     }
    // })
})

app.post("/submit", (req, res) => {
    const submittedSecret = req.body.secret
    User.findById(req.user.id, (err, foundUser) => {
        if (err) {
            console.log(err);
            res.redirect("/submit")
        }
        else {
            if (foundUser) {
                foundUser.secret = submittedSecret
                foundUser.save((err) => {
                    if (err) {
                        console.log(err);
                    }
                    else {
                        res.redirect("/secrets")
                    }
                })
            }
        }
    })
})

app.listen(3000, () => {
    console.log("Server started");
})
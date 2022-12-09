require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const TwitterStrategy = require('passport-twitter');
const findOrCreate = require('mongoose-findorcreate');


const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

app.use(session({
  secret:"thisisthesessionsecretforcookies.",
  resave:false,
  saveUninitialized:false
}));

app.use(passport.initialize());
app.use(passport.session());






mongoose.connect("mongodb://localhost:27017/userDB");
mongoose.Promise = global.Promise;


const userSchema = new mongoose.Schema({
  email : String ,
  password : String,
  googleId: String,
  secret:String,
  facebookId:String,
  twitterId:String
});


userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);



const User = new mongoose.model('User' , userSchema);


// use static authenticate method of model in LocalStrategy
passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture
    });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets",

  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new TwitterStrategy({
    consumerKey:  process.env.TWITTER_CONSUMER_KEY,
    consumerSecret:  process.env.TWITTER_CONSUMER_SECRET,
    callbackURL: "http://localhost:3000/auth/twitter/secrets"
  },
  function(token, tokenSecret, profile, cb) {
    User.findOrCreate({ twitterId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));



app.get('/',function(req,res){
  res.render('home');
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));


  app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {

    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });


  app.get('/auth/facebook',
  passport.authenticate('facebook', { authType: 'reauthenticate', scope: ['public_profile'] }));


  app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });


app.get('/auth/twitter',
passport.authenticate('twitter'));

app.get('/auth/twitter/secrets',
  passport.authenticate('twitter', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get('/login',function(req,res){
  res.render('login');
});

app.get('/submit',function(req,res){
  if(req.isAuthenticated()){
    res.render('submit');
  }else{
    res.redirect('/login');
  }
});

app.post('/submit' , function(req ,res){
  const submitedSecret = req.body.secret ;

  User.findById(req.user.id , function(err , foundUser){
    if(err){
      console.log(err);
    }if(foundUser){
      foundUser.secret = submitedSecret;
      foundUser.save(function(){
        res.redirect('/secrets');
      });
    }
  })

});

app.get('/register',function(req,res){
  res.render('register');
});

app.get('/secrets',function(req,res){
  User.find({'secret' : {$ne : null}} , function(err , foundUsers){
    if (err){
      console.log(err);
    }if(foundUsers){
      res.render('secrets' , {usersWithSecrets : foundUsers});
    }
  });
});

app.get('/logout',function(req,res){
  req.logout(function(err) {
   if (err) { return next(err); }
   res.redirect('/');
 });
});

app.post('/register',function(req,res){

  User.register({username: req.body.username} , req.body.password , function(error , user){
    if(error){
      console.log(error);
      res.redirect('/register');
    }else{
      passport.authenticate('local')(req ,res , function(){
        res.redirect('/secrets');
      });
    }
  });

});

app.post('/login' , function(req ,res){

  const user = new User ({
    username : req.body.username ,
    password : req.body.password
  });

  req.login(user , function(error){
    if(error){
      console.log(erro);
      res.redirect('/login');
    }else{
      passport.authenticate('local')(req ,res , function(){
        res.redirect('/secrets');
      });
    }
  })


});

app.listen(process.env.PORT || 3000, function(req , res){
  console.log('Server Has Started Successfully.');
});

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');




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
  password : String
});


userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model('User' , userSchema);


// use static authenticate method of model in LocalStrategy
passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());


app.get('/',function(req,res){
  res.render('home');
});



app.get('/login',function(req,res){
  res.render('login');
});



app.get('/register',function(req,res){
  res.render('register');
});

app.get('/secrets',function(req,res){
  if(req.isAuthenticated()){
    res.render('secrets');
  }else{
    res.redirect('/login');
  }
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

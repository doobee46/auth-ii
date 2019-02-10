require('dotenv').config();
const express  = require('express');
const jwt      = require('jsonwebtoken')
const helmet   = require('helmet');
const morgan   = require('morgan')
const cors     = require('cors')

const bcrypt   = require('bcryptjs');
const db       = require('./data/dbConfig.js')

const PORT   = 4050;

const server = express();
server.use(express.json()); 
server.use(cors('localhost:4050'))
server.use(
            helmet(),
            morgan('dev'),
          );

//endpoints

function generateToken(user){
  const payload = {
    username: user.username,
    department: user.department
  }
  const secret = process.env.JWT_SECRET
  const options ={
    expiresIn:'10m'
  }
  return jwt.sign(payload, secret, options)
}

server.post("/api/login",(req, res) =>{
  const creds = req.body;
  db("users")
    .where("username", creds.username).first()
    .then(user => { 
    if( user && bcrypt.compareSync(creds.password, user.password)){
      const token = generateToken(user);
      res.status(202).json({msg:"user logged in", token });
    }
    else{
      res.status(401).send("invalid username or password");
    }
    })
    .catch(err =>{
      res.status(500).send(err);
    })
})

server.post("/api/register", (req, res) => {
  const user = req.body;
  user.password = bcrypt.hashSync(user.password);
  db("users")
    .insert(user)
    .then(id => {
      res.status(201).send({ message: `id ${id} created` });
    })
    .catch(err => {
      res.status(500).send(err);
    });
});

function protected(req, res, next ){
  const token = req.headers.authorization
  if(token){
    jwt.verify(token, process.env.JWT_SECRET, (err, decodedToken) =>{
      if(err){
        res.status(401).json({msg:"invalid token"})
      }
      else{
        req.decodedToken = decodedToken;
        next(); 
      }
    })
  }
  else{
    res.status(401).json({msg:"invalid token"})
  }
}

server.get('/api/users',protected ,(req, res) =>{
  db('users')
  .select('id', 'username')
  .then(users => {
    res.json({users, decodedToken: req.decodedToken});
  })
  .catch(err => res.send(err));
})

// server.get('/api/logout', (req, res) => {

// })


//listen
server.listen(PORT, () =>{
  console.log(`\n=== Web API Listening on http://localhost:${PORT} ===\n`);
})
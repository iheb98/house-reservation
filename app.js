const express = require('express');
const app = express();
const mongoose = require('mongoose');
const bodyparser = require("body-parser");
const path = require('path');
const passport = require('passport');
const port = process.env.PORT || 3000;
const cors = require('cors');
require('dotenv/config');

// **************************************** CORS ****************************************
var allowedDomains = ['https://djotech.herokuapp.com', 'http://localhost:4200'];

/*
var corsOptions = {
  origin: 'https://djotech.herokuapp.com',
  optionsSuccessStatus: 200
}
*/

// CROSS ORIGIN RESOURCE SHARING
app.use(cors({
  origin: function (origin, callback) {
    // bypass the requests with no origin (like curl requests, mobile apps, etc )
    if (!origin) return callback(null, true);

    if (allowedDomains.indexOf(origin) === -1) {
      var msg = `This site ${origin} does not have an access. Only specific domains are allowed to access it.`;
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  }
}));
//**************************************************************************************************************

app.use(express.static('.'));

app.use(bodyparser.json());

const usersRoute = require('./routes/users');

app.use('/users', usersRoute)

mongoose.connect(process.env.DB_CONNECTION,
  { useNewUrlParser: true, useUnifiedTopology: true },
  () => {
    console.log('connected to Database');
  });

require('./config/passport')(passport);

app.use('/', (req, res) => {
  res.json({ message: "Test successful" });
})

app.listen(port);
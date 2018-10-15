// Based on http://expressjs.com/en/starter/hello-world.html
// https://creativecommons.org/licenses/by-sa/3.0/us/
//
// Extended to support configurable port and message.

const express = require('express')

const app = express()
const config = require('./config.json')

app.get('/', function (req, res) {
  res.send(config.message||'Hello Welcome to Ye Olde Brewery Of Node Code!')
})

app.listen(config.port, function () {
  console.log('listening on port ' + String(config.port||3000))
})
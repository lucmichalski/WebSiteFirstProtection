
const express = require('express')
const bodyParser = require('body-parser')
const expressLayouts = require('express-ejs-layouts')
const app = express()
const port = process.env.PORT || 5000

var fs=require('fs');
var data=fs.readFileSync('lastreport.json', 'utf8');
var session = 0

app.set('view engine', 'ejs')     // Setamos que nossa engine será o ejs
app.use(expressLayouts)           // Definimos que vamos utilizar o express-ejs-layouts na nossa aplicação
app.use(bodyParser.urlencoded())  // Com essa configuração, vamos conseguir parsear o corpo das requisições

app.use(express.static(__dirname + '/public'))


var report=JSON.parse(data);
//console.log(report);


app.listen(port, () => {
    console.log(`Service on http://localhost:${port}`)
})

app.get('/', (req, res) => {
  if(session) {
    res.render('pages/welcome', {

      sessao: session,
      report: report
    })
  } else {
    res.render('pages/home', {
      sessao: session
    })
  }
})

app.get('/main', (req, res) => {
  res.render('pages/welcome', {
    sessao: session,
    report: report
  })
})

app.post('/login', (req, res) => {
  session = [{
        name: "Usuario",
        id: "bla"
  }]
  res.render('pages/welcome', {

    sessao: session,
    report: report
  })
})

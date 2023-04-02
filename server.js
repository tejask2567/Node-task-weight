const express =require('express');
const app = express()
const bodyParser=require('body-parser')
const mongoose = require('mongoose')
const User = require('./model/user')
const bcrypt = require('bcryptjs')
const cors=require('cors')
const jwt = require('jsonwebtoken')


const JWT_SECRET = 'sdjkfh8923yhjdksbfma@#*(&@*!^#&@bhjb2qiuhesdbhjdsfg839ujkdhfjk'

mongoose.connect('mongodb://localhost:27017/mongo',{
    useNewUrlParser:true,
    useUnifiedTopology:true,
    
})
app.use('/img', express.static('img'))
app.use(bodyParser.json())
/* app.use(express.urlencoded({ extended: true }));

app.use(express.json()); */
app.use(cors());
//routes
app.get("/",(req,res)=>{
    res.render("index.ejs")
})

app.get('/login',(req,res)=>{
    res.render('login.ejs')
})
app.get('/register',(req,res)=>{
    res.render('register.ejs')
})

app.post('/api/register', async(req,res)=>{
    //console.log(req.body)
    const{username,email,password:plainTextPassword}=req.body
	if (!username || typeof username !== 'string') {
		return res.json({ status: 'error', error: 'Invalid username' })
	}

	if (!plainTextPassword || typeof plainTextPassword !== 'string') {
		return res.json({ status: 'error', error: 'Invalid password' })
	}

	if (plainTextPassword.length < 7) {
		return res.json({
			status: 'error',
			error: 'Password too small. Should be atleast 8 characters'
		})
	}
    const password = await bcrypt.hash(plainTextPassword, 10)
    try {
		const response = await User.create({
			username,
            email,
			password
		})
		console.log('User created successfully: ', response)
	} catch (error) {
		if (error.code === 11000 || error.code === 'ERR_HTTP_HEADERS_SENT' ) {
			// duplicate key
			return res.json({ status: 'error', error: 'Email already in use' })
		}
	    return res.sendStatus(500).send({
            message:error.message|| "some error occured"})
	}
    res.json({status:'ok'})
})

app.post('/api/login', async(req,res)=>{
	
	const { username, password } = req.body
	const user = await User.findOne({ username }).lean()

	if (!user) {
		return res.json({ status: 'error', error: 'Invalid email/password' })
	}

	if (await bcrypt.compare(password, user.password)) {
		// the username, password combination is successful

		const token = jwt.sign(
			{
				id: user._id,
				username: user.username
			},
			JWT_SECRET
		)
		//return res.redirect('http://localhost:3000/')
		return res.json({ status: 'ok', data: token })
	}

	res.json({ status: 'error', error: 'Invalid email/password' })
})

app.listen("3000") 
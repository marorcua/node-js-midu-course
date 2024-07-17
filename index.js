import { PORT, SECRET } from './config.js'
import express, { json } from 'express'
import { UserRespository } from './user-repository.js'
import jsonwebtoken from 'jsonwebtoken'
import cookieParser from 'cookie-parser'

const app = express()
app.set('view engine', 'ejs')
app.use(express.json())
app.use(cookieParser())

app.use((req, res, next) => {
  const token = req.cookies.access_token
  req.session = { user: null }
  try {
    const data = jsonwebtoken.verify(token, SECRET)
    req.session.user = { ...data, message: '' }
  } catch (error) {
    req.session.user = { message: 'none' }
  }
  next()
})

app.get('/', async (req, res) => {
  console.log('/')
  const { user } = req.session
  res.render('index', user)
})

app.post('/login', async (req, res) => {
  console.log('login')
  const { username, password } = req.body
  try {
    const user = await UserRespository.login({ username, password })
    const token = await jsonwebtoken.sign(
      {
        id: user._id,
        username: user.username
      },
      SECRET,
      { expiresIn: '1h' }
    )
    const refreshToken = await jsonwebtoken.sign(
      {
        id: user._id,
        username: user.username,
        token
      },
      SECRET,
      { expiresIn: '1d' }
    )
    res
      .cookie('access_token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: true, //mismo dominio
        maxAge: 1000 * 60 * 60 //1 hora
      })
      .send({ user, token })
  } catch (err) {
    console.log('error', err)
    res.status(400).send(err.message)
  }
})

app.post('/register', async (req, res) => {
  console.log('register')
  const { username, password } = req.body
  try {
    const id = await UserRespository.create({ username, password })
    res.send({ id })
  } catch (err) {
    console.log(err)
    res.status(400).send(err.message)
  }
})
app.post('/logout', (req, res) => {
  res.clearCookie('access_token').json({ message: 'Logout succeeded' })
})
app.get('/protected', async (req, res) => {
  const { user } = req.session
  if (!user) res.status(403).send('Error de token')
  res.render('protected', user)
})

app.listen(PORT, () => {
  console.log('server listening to port ', PORT)
})

import DBLocal from 'db-local'

import crypto from 'crypto'
import bcrypt from 'bcrypt'
const { Schema } = new DBLocal({ path: './db' })
import { SALT_ROUNDS } from './config.js'

const User = Schema('User', {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true }
})

export class UserRespository {
  static async create({ username, password }) {
    Validation.Password(password)
    Validation.Username(username)

    const user = User.findOne({ username })
    if (user) throw new Error('user already exists')

    const id = crypto.randomUUID()
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS)

    User.create({
      id,
      username,
      password: hashedPassword
    }).save()

    return id
  }

  static async login({ username, password }) {
    console.log({ username, password })
    Validation.Username(username)
    Validation.Password(password)

    const user = User.findOne({ username })
    if (!user) throw new Error('User not found')

    const isValid = await bcrypt.compare(password, user.password)
    if (!isValid) throw new Error('Password not correct')

    const { password: _, ...publicUser } = user

    return publicUser
  }
  static logout({ username, password }) {}
}

class Validation {
  static Username(username) {
    if (typeof username !== 'string') throw new Error('Username must be string')
    if (username.length < 3) throw new Error('Username must be longer than 3')
  }

  static Password(password) {
    if (typeof password !== 'string') {
      throw new Error('Password must be longer than 3')
    }
    if (password.length < 6) throw new Error('Password must be longer than 6')
  }
}

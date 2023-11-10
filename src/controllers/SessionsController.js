const knex = require("../database/knex");
const AppError = require("../utils/AppError");
const { compare } = require('bcryptjs');
const authConfig = require("../configs/auth");
const { sign } = require("jsonwebtoken");


class SessionsController {
  async create(request, response) {
    const { email, password } = request.body;

    const user = await knex('users').where({ email }).first();

    if (!user) {
      throw new AppError("E-mail ou senha incorreta", 401);
    }

    if (!password) {
      throw new AppError("Informe a senha do usuário", 401);
    }

    if (password) {
      const validPassword = await compare(password, user.password);

      if (!validPassword) {
        throw new AppError("E-mail ou senha incorreta");
      }
    }

    const { secret, expiresIn } = authConfig.jwt;
    const token = sign({}, secret, {
      subject: String(user.id),
      expiresIn
    });

    return response.json({ user, token });
  }
}



module.exports = SessionsController;
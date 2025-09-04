import validator from 'validator';
import { type Request, type Response, type NextFunction } from 'express';
import * as challengeUtils from '../lib/challengeUtils';
import { challenges } from '../data/datacache';
import { BasketModel } from '../models/basket';
import * as security from '../lib/insecurity';
import { UserModel } from '../models/user';
import * as models from '../models/index';
import * as utils from '../lib/utils';

export function login() {
  async function afterLogin(user: { data: UserModel; bid: number }, res: Response, next: NextFunction) {
    try {
      const [basket] = await BasketModel.findOrCreate({ where: { UserId: user.data.id } });
      const token = security.authorize(user);
      user.bid = basket.id;
      security.authenticatedUsers.put(token, user);

      // Send JWT token to client
      res.json({
        authentication: {
          token,
          bid: basket.id,
          umail: user.data.email
        }
      });
    } catch (error) {
      next(error);
    }
  }

  return async (req: Request, res: Response, next: NextFunction) => {
    const email = req.body.email || '';
    const password = req.body.password || '';

    if (!validator.isEmail(email)) {
      return res.status(400).send('Invalid email');
    }

    const safeEmail = validator.normalizeEmail(email) || '';

    try {
      const authenticatedUser = await models.sequelize.query(
        `SELECT * FROM Users WHERE email = '${safeEmail}' AND deletedAt IS NULL`,
        { model: UserModel, plain: true }
      );

      const user = utils.queryResultToJson(authenticatedUser);

      if (!user.data?.id || !security.comparePassword(password, user.data.password || '')) {
        return res.status(401).send(res.__('Invalid email or password.'));
      }

      if (user.data.totpSecret !== '') {
        res.status(401).json({
          status: 'totp_token_required',
          data: {
            tmpToken: security.authorize({
              userId: user.data.id,
              type: 'password_valid_needs_second_factor_token'
            })
          }
        });
      } else {
        afterLogin({ data: user.data, bid: 0 }, res, next);
      }
    } catch (error) {
      console.error(error);
      next(error);
    }
  };
}

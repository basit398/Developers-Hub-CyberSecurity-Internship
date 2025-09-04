import config from 'config';
import {
  type InferAttributes,
  type InferCreationAttributes,
  Model,
  DataTypes,
  type CreationOptional,
  type Sequelize
} from 'sequelize';
import * as challengeUtils from '../lib/challengeUtils';
import * as utils from '../lib/utils';
import { challenges } from '../data/datacache';
import * as security from '../lib/insecurity';
import bcrypt from 'bcryptjs';

class User extends Model<InferAttributes<User>, InferCreationAttributes<User>> {
  declare id: CreationOptional<number>;
  declare username: string | undefined;
  declare email: CreationOptional<string>;
  declare password: CreationOptional<string>;
  declare role: CreationOptional<string>;
  declare deluxeToken: CreationOptional<string>;
  declare lastLoginIp: CreationOptional<string>;
  declare profileImage: CreationOptional<string>;
  declare totpSecret: CreationOptional<string>;
  declare isActive: CreationOptional<boolean>;
}

const UserModelInit = (sequelize: Sequelize) => {
  User.init(
    {
      id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
      username: {
        type: DataTypes.STRING,
        defaultValue: '',
        set(username: string) {
          username = utils.isChallengeEnabled(challenges.persistedXssUserChallenge)
            ? security.sanitizeLegacy(username)
            : security.sanitizeSecure(username);
          this.setDataValue('username', username);
        }
      },
      email: {
        type: DataTypes.STRING,
        unique: true,
        set(email: string) {
          email = utils.isChallengeEnabled(challenges.persistedXssUserChallenge)
            ? email
            : security.sanitizeSecure(email);
          this.setDataValue('email', email);
        }
      },
      password: {
        type: DataTypes.STRING,
        set(clearTextPassword: string) {
          const hashedPassword = security.hash(clearTextPassword);
          this.setDataValue('password', hashedPassword);
        }
      },
      role: {
        type: DataTypes.STRING,
        defaultValue: 'customer',
        validate: { isIn: [['customer', 'deluxe', 'accounting', 'admin']] },
        set(role: string) {
          const profileImage = this.getDataValue('profileImage');
          if (
            role === security.roles.admin &&
            (!profileImage || profileImage === '/assets/public/images/uploads/default.svg')
          ) {
            this.setDataValue('profileImage', '/assets/public/images/uploads/defaultAdmin.png');
          }
          this.setDataValue('role', role);
        }
      },
      deluxeToken: { type: DataTypes.STRING, defaultValue: '' },
      lastLoginIp: { type: DataTypes.STRING, defaultValue: '0.0.0.0' },
      profileImage: { type: DataTypes.STRING, defaultValue: '/assets/public/images/uploads/default.svg' },
      totpSecret: { type: DataTypes.STRING, defaultValue: '' },
      isActive: { type: DataTypes.BOOLEAN, defaultValue: true }
    },
    { tableName: 'Users', paranoid: true, sequelize }
  );

  User.addHook('afterValidate', async (user: User) => {
    if (
      user.email &&
      user.email.toLowerCase() === `acc0unt4nt@${config.get<string>('application.domain')}`.toLowerCase()
    ) {
      await Promise.reject(new Error('Nice try, but this is not how the "Ephemeral Accountant" challenge works!'));
    }
  });
};

export { User as UserModel, UserModelInit };

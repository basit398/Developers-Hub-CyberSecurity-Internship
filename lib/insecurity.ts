import fs from 'node:fs';
import crypto from 'node:crypto';
import { type Request, type Response, type NextFunction } from 'express';
import { type UserModel } from 'models/user';
import expressJwt from 'express-jwt';
import jwt from 'jsonwebtoken';
import jws from 'jws';
import sanitizeHtmlLib from 'sanitize-html';
import sanitizeFilenameLib from 'sanitize-filename';
import * as utils from './utils';
import bcrypt from 'bcryptjs';

// eslint-disable-next-line @typescript-eslint/prefer-ts-expect-error
// @ts-ignore
import z85 from 'z85';

export const publicKey = fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'placeholder-public-key';
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8iMz0EaM4BKUqYsIa+ndv3NAn2RxCd5ubVdJJcX43zO6Ko0TFEZx/65gY3BE0O6syCEmUP4qbSd6exou/F+WTISzbQ5FBVPVmhnYhG/kpwt/cIxK5iUn5hm+4tQIDAQABAoGBAI+8xiPoOrA+KMnG/T4jJsG6TsHQcDHvJi7o1IKC/hnIXha0atTX5AUkRRce95qSfvKFweXdJXSQ0JMGJyfuXgU6dI0TcseFRfewXAa/ssxAC+iUVR6KUMh1PE2wXLitfeI6JLvVtrBYswm2I7CtY0q8n5AGimHWVXJPLfGV7m0BAkEA+fqFt2LXbLtyg6wZyxMA/cnmt5Nt3U2dAu77MzFJvibANUNHE4HPLZxjGNXN+a6m0K6TD4kDdh5HfUYLWWRBYQJBANK3carmulBwqzcDBjsJ0YrIONBpCAsXxk8idXb8jL9aNIg15Wumm2enqqObahDHB5jnGOLmbasizvSVqypfM9UCQCQl8xIqy+YgURXzXCN+kwUgHinrutZms87Jyi+D8Br8NY0+Nlf+zHvXAomD2W5CsEK7C+8SLBr3k/TsnRWHJuECQHFE9RA2OP8WoaLPuGCyFXaxzICThSRZYluVnWkZtxsBhW2W8z1b8PvWUE7kMy7TnkzeJS2LSnaNHoyxi7IaPQUCQCwWU4U+v4lD7uYBw00Ga/xt+7+UqFPlPVdz1yyr4q24Zxaw0LgmuEvgU5dycq8N7JxjTubX0MIRR+G9fmDBBl8=\r\n-----END RSA PRIVATE KEY-----'

export interface ResponseWithUser {
  status?: string;
  data: UserModel;
  iat?: number;
  exp?: number;
  bid?: number;
}

interface IAuthenticatedUsers {
  tokenMap: Record<string, ResponseWithUser>;
  idMap: Record<string, string>;
  put: (token: string, user: ResponseWithUser) => void;
  get: (token?: string) => ResponseWithUser | undefined;
  tokenOf: (user: UserModel) => string | undefined;
  from: (req: Request) => ResponseWithUser | undefined;
  updateFrom: (req: Request, user: ResponseWithUser) => any;
}

// ---------- PASSWORD HASHING ----------
export const hash = (password: string): string => {
  const salt = bcrypt.genSaltSync(10);
  return bcrypt.hashSync(password, salt);
};

export const comparePassword = (plain: string, hashed: string): boolean => {
  return bcrypt.compareSync(plain, hashed);
};
// ------------------------------------

export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex');

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = '%00';
  if (utils.contains(str, nullByte)) {
    return str.substring(0, str.indexOf(nullByte));
  }
  return str;
};

export const isAuthorized = () => expressJwt(({ secret: publicKey }) as any);
export const denyAll = () => expressJwt({ secret: '' + Math.random() } as any);

// ---------- JWT AUTHENTICATION ----------
export const authorize = (user: any) => jwt.sign({ id: user.data.id }, privateKey, { expiresIn: '6h', algorithm: 'RS256' });
export const verify = (token: string) => token ? (jws.verify as ((token: string, secret: string) => boolean))(token, publicKey) : false;
export const decode = (token: string) => jws.decode(token)?.payload;

// ---------- SANITIZATION & ROLES ----------
export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html);
export const sanitizeLegacy = (input = '') => input.replace(/<(?:\w+)\W+?[\w]/gi, '');
export const sanitizeFilename = (filename: string) => sanitizeFilenameLib(filename);
export const sanitizeSecure = (html: string): string => {
  const sanitized = sanitizeHtml(html);
  return sanitized === html ? html : sanitizeSecure(sanitized);
};

export const roles = {
  customer: 'customer',
  deluxe: 'deluxe',
  accounting: 'accounting',
  admin: 'admin'
};

export const authenticatedUsers: IAuthenticatedUsers = {
  tokenMap: {},
  idMap: {},
  put: function (token: string, user: ResponseWithUser) {
    this.tokenMap[token] = user;
    this.idMap[user.data.id.toString()] = token;
  },
  get: function (token?: string) {
    return token ? this.tokenMap[utils.unquote(token)] : undefined;
  },
  tokenOf: function (user: UserModel) {
    return user ? this.idMap[user.id.toString()] : undefined;
  },
  from: function (req: Request) {
    const token = utils.jwtFrom(req);
    return token ? this.get(token) : undefined;
  },
  updateFrom: function (req: Request, user: ResponseWithUser) {
    const token = utils.jwtFrom(req);
    this.put(token, user);
  }
};

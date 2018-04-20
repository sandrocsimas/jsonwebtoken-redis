'use strict';

const Promise = require('bluebird');
const jwt = require('jsonwebtoken');
const uid = require('mongoid-js');
const ms = require('ms');
const cloneDeep = require('lodash.clonedeep');

const signAsync = Promise.promisify(jwt.sign);
const verifyAsync = Promise.promisify(jwt.verify);

function JwtRedis(client, options) {

  const prefix = options && options.prefix ? options.prefix : 'session:';
  const defaultExpiresKeyIn = options && options.expiresKeyIn ? options.expiresKeyIn : null;

  const setAsync = Promise.promisify(client.set, {context: client});
  const delAsync = Promise.promisify(client.del, {context: client});
  const existsAsync = Promise.promisify(client.exists, {context: client});
  const expireAsync = Promise.promisify(client.expire, {context: client});

  function getKey(jti) {
    return prefix + jti;
  }

  this.sign = async (payload, secret, options) => {
    options = cloneDeep(options) || {};
    payload = cloneDeep(payload) || {};
    const expiresIn = options.expiresIn || payload.exp;
    const expiresKeyIn = options.expiresKeyIn || defaultExpiresKeyIn;
    if (!expiresIn && expiresKeyIn) {
      payload.expk = typeof expiresKeyIn === 'string' ? ms(expiresKeyIn) : expiresKeyIn;
    }
    let jti = options.jwtid || payload.jti;
    if (!jti) {
      jti = uid();
      options.jwtid = jti;
    }
    delete options.expiresKeyIn;
    const token = await signAsync(payload, secret, options);
    const decoded = await this.decode(token);
    if (decoded.exp) {
      await setAsync(getKey(decoded.jti), 'true', 'EX', decoded.exp - Math.floor(Date.now() / 1000));
    } else if (decoded.expk) {
      await setAsync(getKey(decoded.jti), 'true', 'EX', decoded.expk);
    } else {
      await setAsync(getKey(decoded.jti), 'true');
    }
    return token;
  };

  this.verify = async (token, secret, options) => {
    const decoded = await this.decode(token);
    if (decoded.jti) {
      const exists = await existsAsync(getKey(decoded.jti));
      if (!exists) {
        throw new JwtRedis.TokenExpiredError();
      }
    }
    try {
      return await verifyAsync(token, secret, options);
    } catch (err) {
      if (err instanceof JwtRedis.TokenExpiredError) {
        await this.destroyByJti(decoded.jti);
      }
      throw err;
    }
  };

  this.decode = async (token, options) => {
    return jwt.decode(token, options);
  };

  this.destroy = async (token) => {
    const decoded = await this.decode(token);
    return this.destroyByJti(decoded.jti);
  };

  this.destroyByJti = async (jti) => {
    if (jti) {
      await delAsync(getKey(jti));
    }
  };

  this.touch = async (token) => {
    const decoded = await this.decode(token);
    if (decoded.jti && decoded.expk && !decoded.exp) {
      await expireAsync(getKey(decoded.jti), decoded.expk);
    }
  };
}

JwtRedis.JsonWebTokenError = jwt.JsonWebTokenError;
JwtRedis.NotBeforeError = jwt.NotBeforeError;
JwtRedis.TokenExpiredError = jwt.TokenExpiredError;

// eslint-disable-next-line prefer-destructuring, no-multi-assign
exports = module.exports = JwtRedis;

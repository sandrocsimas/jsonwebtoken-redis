'use strict';

const jwt = require('jsonwebtoken');
const uuid = require('uuid/v4');
const ms = require('ms');
const cloneDeep = require('lodash.clonedeep');

function JwtRedis(client, options) {

  const PromiseImpl = options && options.promiseImpl ? options.promiseImpl : Promise;
  const prefix = options && options.prefix ? options.prefix : 'session:';
  const defaultExpiresKeyIn = options && options.expiresKeyIn ? options.expiresKeyIn : null;

  function promisify(func, context) {
    return {
      func,
      context,
      exec: (...args) => {
        return new PromiseImpl((resolve, reject) => {
          func.apply(context, [...args, (err, result) => {
            if (err) {
              reject(err);
            } else {
              resolve(result);
            }
          }]);
        });
      },
    };
  }

  const signAsync = promisify(jwt.sign);
  const verifyAsync = promisify(jwt.verify);
  const setAsync = promisify(client.set, client);
  const delAsync = promisify(client.del, client);
  const existsAsync = promisify(client.exists, client);
  const expireAsync = promisify(client.expire, client);

  function getKey(jti) {
    return prefix + jti;
  }

  async function destroyByJti(jti) {
    if (jti) {
      await delAsync.exec(getKey(jti));
    }
  }

  this.sign = async (payload, secret, options) => {
    options = cloneDeep(options) || {};
    payload = cloneDeep(payload) || {};
    const expiresIn = options.expiresIn || payload.exp;
    const expiresKeyIn = options.expiresKeyIn || defaultExpiresKeyIn;
    if (!expiresIn && expiresKeyIn) {
      if (typeof expiresKeyIn === 'string') {
        payload.expk = Math.floor(ms(expiresKeyIn) / 1000);
      } else {
        payload.expk = expiresKeyIn;
      }
    }
    let jti = options.jwtid || payload.jti;
    if (!jti) {
      jti = uuid();
      options.jwtid = jti;
    }
    delete options.expiresKeyIn;
    const token = await signAsync.exec(payload, secret, options);
    const decoded = await this.decode(token);
    if (decoded.exp) {
      await setAsync.exec(getKey(decoded.jti), 'true', 'EX', decoded.exp - Math.floor(Date.now() / 1000));
    } else if (decoded.expk) {
      await setAsync.exec(getKey(decoded.jti), 'true', 'EX', decoded.expk);
    } else {
      await setAsync.exec(getKey(decoded.jti), 'true');
    }
    return token;
  };

  this.verify = async (token, secret, options) => {
    const decoded = await this.decode(token);
    if (decoded.jti) {
      const exists = await existsAsync.exec(getKey(decoded.jti));
      if (!exists) {
        throw new JwtRedis.TokenExpiredError();
      }
    }
    try {
      return await verifyAsync.exec(token, secret, options);
    } catch (err) {
      if (err instanceof JwtRedis.TokenExpiredError) {
        await destroyByJti(decoded.jti);
      }
      throw err;
    }
  };

  this.decode = async (token, options) => {
    return PromiseImpl.resolve(jwt.decode(token, options));
  };

  this.touch = async (token) => {
    const decoded = await this.decode(token);
    if (decoded.jti && decoded.expk && !decoded.exp) {
      await expireAsync.exec(getKey(decoded.jti), decoded.expk);
    }
  };

  this.destroy = async (token) => {
    const decoded = await this.decode(token);
    await destroyByJti(decoded.jti);
  };
}

JwtRedis.JsonWebTokenError = jwt.JsonWebTokenError;
JwtRedis.NotBeforeError = jwt.NotBeforeError;
JwtRedis.TokenExpiredError = jwt.TokenExpiredError;

// eslint-disable-next-line prefer-destructuring, no-multi-assign
exports = module.exports = JwtRedis;

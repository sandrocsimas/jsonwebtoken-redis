'use strict';

/* eslint-env mocha */

const JwtRedis = require('..');
const {expect} = require('chai');
const redis = require('redis-mock');
const Promise = require('bluebird');

// const PREFIX = 'session:';
const SECRET = 'shhhhhh';

const client = redis.createClient();
const jwtRedis = new JwtRedis(client, {
  promiseImpl: Promise,
});

// const getAsync = Promise.promisify(client.get, {context: client});

// function getKey(jti) {
//   return PREFIX + jti;
// }function getKey(jti) {
//   return PREFIX + jti;
// }

describe('JwtRedis', () => {
  describe('#sign()', () => {
    it('should sign a token with random jti', async () => {
      const token = await jwtRedis.sign({userId: '1'}, SECRET);
      expect(token).to.exist;
      const decoded = await jwtRedis.decode(token);
      expect(decoded.jti).to.have.lengthOf(36);
    });

    it('should sign a token with custom jti in options', async () => {
      const token = await jwtRedis.sign({userId: '1'}, SECRET, {jwtid: '1'});
      expect(token).to.exist;
      const decoded = await jwtRedis.decode(token);
      expect(decoded.jti).to.be.equal('1');
    });

    it('should sign a token with custom jti in payload', async () => {
      const token = await jwtRedis.sign({userId: '1', jti: '1'}, SECRET);
      expect(token).to.exist;
      const decoded = await jwtRedis.decode(token);
      expect(decoded.jti).to.be.equal('1');
    });

    it('should sign a token without expiration', async () => {
      const token = await jwtRedis.sign({userId: '1'}, SECRET);
      expect(token).to.exist;
      const decoded = await jwtRedis.decode(token);
      expect(decoded).to.not.have.property('exp');
      expect(decoded).to.not.have.property('expk');
    });

    it('should sign a token with JWT expiration in options', async () => {
      const token = await jwtRedis.sign({userId: '1'}, SECRET, {expiresIn: '5 seconds'});
      expect(token).to.exist;
      const decoded = await jwtRedis.decode(token);
      expect(decoded).to.have.property('exp').that.is.a('number');
      expect(decoded).to.not.have.property('expk');
    });

    it('should sign a token with JWT expiration in payload', async () => {
      const token = await jwtRedis.sign({userId: '1', exp: Math.floor(Date.now() / 1000) + 5}, SECRET);
      expect(token).to.exist;
      const decoded = await jwtRedis.decode(token);
      expect(decoded).to.have.property('exp').that.is.a('number');
      expect(decoded).to.not.have.property('expk');
    });

    it('should sign a token with JWT expiration in options overriding Redis expiration', async () => {
      const token = await jwtRedis.sign({userId: '1'}, SECRET, {expiresIn: '5 seconds', expiresKeyIn: '10 seconds'});
      expect(token).to.exist;
      const decoded = await jwtRedis.decode(token);
      expect(decoded).to.have.property('exp').that.is.a('number');
      expect(decoded).to.not.have.property('expk');
    });

    it('should sign a token with JWT expiration in payload overriding Redis expiration', async () => {
      const token = await jwtRedis.sign({userId: '1'}, SECRET, {expiresIn: '10 seconds', expiresKeyIn: '20 seconds'});
      const decoded = await jwtRedis.decode(token);
      expect(token).to.exist;
      expect(decoded).to.have.property('exp').that.is.a('number');
      expect(decoded).to.not.have.property('expk');
    });

    it('should sign a token with Redis expiration', async () => {
      const token = await jwtRedis.sign({userId: '1'}, SECRET, {expiresKeyIn: 5});
      expect(token).to.exist;
      const decoded = await jwtRedis.decode(token);
      expect(decoded.expk).to.be.equal(5);
      expect(decoded).to.not.have.property('exp');
    });

    it('should sign a token with Redis expiration as string', async () => {
      const token = await jwtRedis.sign({userId: '1'}, SECRET, {expiresKeyIn: '15 seconds'});
      expect(token).to.exist;
      const decoded = await jwtRedis.decode(token);
      expect(decoded.expk).to.be.equal(15);
      expect(decoded).to.not.have.property('exp');
    });
  });

  describe('#verify()', () => {
    it('should verify the token', async () => {
      const token = await jwtRedis.sign({userId: '1'}, SECRET);
      const decoded = await jwtRedis.verify(token, SECRET);
      expect(decoded.userId).to.equal('1');
      expect(decoded).to.have.property('jti');
      expect(decoded).to.have.property('iat');
    });

    it('should throw token expired error when token do not exist in Redis', async () => {
      try {
        const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxIiwiaWF0IjoxNTI0MjAwNDUyLCJqdGkiOiI1YWQ5NzQwNDk2NGUyNDRlOTkwMDAwMGEifQ.Vo9XbaiLvckk6Yp_tHieGla7eLGEWFwsMO-Hz9Fzb5M';
        await jwtRedis.verify(token, SECRET);
      } catch (err) {
        expect(err).to.be.an.instanceof(JwtRedis.TokenExpiredError);
      }
    });
  });

  describe('#decode()', () => {
    it('should decode the token', async () => {
      const token = await jwtRedis.sign({userId: '1'}, SECRET);
      const decoded = await jwtRedis.decode(token, {complete: true});
      expect(decoded).to.have.property('header');
      expect(decoded).to.have.property('payload');
      expect(decoded).to.have.property('signature');
      expect(decoded.payload.userId).to.equal('1');
      expect(decoded.payload).to.have.property('jti');
      expect(decoded.payload).to.have.property('iat');
    });
  });

  describe('#destroy()', () => {
    it('should remove the token from Redis', async () => {
      const token = await jwtRedis.sign({userId: '1'}, SECRET);
      await jwtRedis.destroy(token);
    });
  });

  describe('#touch()', () => {
    it('should update the token expiration in Redis', async () => {
      const token = await jwtRedis.sign({userId: '1'}, SECRET);
      await jwtRedis.touch(token);
    });

    it('should not update the token expiration in Redis when JWT expiration is defined', async () => {
      const token = await jwtRedis.sign({userId: '1'}, SECRET, {expiresIn: '10 seconds'});
      await jwtRedis.touch(token);
    });
  });
});

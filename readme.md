# jsonwebtoken-redis

This library completely repeats the entire functionality of the library [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken), with four important additions:
1. The token expiration time can be completely managed by Redis.
2. You can invalidate the token by removing it from Redis.
3. You can postpone the expiration a token.
4. There's no callback. All functions returns Promises.

# Installation

```javascript
npm install jsonwebtoken-redis
```

# Quick start

```javascript
const Redis = require('redis');
const redis = new Redis();
const JwtRedis =  require('jsonwebtoken-redis');

const jwtRedis = new JwtRedis(redis, {
  prefix: 'session:' // The prefix used in Redis keys (optional). Defaults to "session:".
  expiresKeyIn: '24 hours' // The default Redis expiration time (optional)
  promiseImpl: Promise // Custom promise library (optional). Defaults to native Promise.
});

const secret = 'shhhhhh';
const payload = {
  scope: 'user',
  user: '1',
};

// Sign function call overriding the default Redis expiration time provided above
jwtRedis.sign(payload, secret, {expiresKeyIn: '48 hours'}).bind({}).then((token) => {
  this.token = token;
  // Returns the decoded payload without verifying if the signature is valid
  return jwtRedis.decode(token, secret, {complete: true});
}).then((decoded) => {
  // Returns the decoded payload verifying if the signature is valid
  return jwtRedis.verify(this.token, secret);
}).then((decoded) => {
  // Increases the expiration time by 48 hours
  return jwtRedis.touch(this.token);
}).then(() => {
  // Removes the token from Redis, invalidating it in the next "verify" function calls.
  return jwtRedis.destroy(this.token);
});
```

# Expiration time managed by Redis

There's a new option ````expiresKeyIn```` when you call [sign](https://www.npmjs.com/package/jsonwebtoken#jwtsignpayload-secretorprivatekey-options-callback).
This option is used to set the expiration time of the key/value created in Redis.
Using this option the expiration time is completely managed by Redis, in other words, the key/value is created in Redis through the command ````expire````. The token it self doesn't contain any expiration data.

```javascript
jwtRedis.sign(payload, secret, {expiresKeyIn: '48 hours'}).then((token) => {

});
```

You can continue to use the option ````expiresIn```` or the payload attribute ````exp````, but the option ````expiresKeyIn```` will be completely ignore.
The key/value will be created in Redis with the expiration based on jwt option or payload attriute mentioned previously.

Attention: Implementing this way, you can't postpone the expiration in Redis because the token it self will expire.

# Defining the jti claim

The "jti" (JWT ID) claim provides a unique identifier for the JWT. This is used to create the key for the token in Redis.
If you don't provide the "jti", a new one will be generated using [uuid](https://www.npmjs.com/package/uuid) version 4 (random).

```javascript
const jwtRedis = new JwtRedis(client, {prefix: 'session:'})
const payload = {jti: 'test'}; // The key for the token in Redis will be "session:test"
const secret = 'shhhhhh';
jwtRedis.sign(payload, secret, {expiresKeyIn: '1 hour'}).then((token) => {
  return jwtRedis.decode(token, secret);
}).then((decoded) => {
  console.log(decoded.jti) // Will print "test"
});
```

# Touching the token

When you set the jwt expiration time, you can't change it anymore. By using the option ````expiresKeyIn```` when you call ````sign````, you have the power to postpone the expiration time.

```javascript
jwtRedis.sign(payload, secret, {expiresKeyIn: '1 hour'}).then((token) => {
  // Do what you need here
});
// After 30 minutes...
jwtRedis.touch(token).then(() => {
  // Now the token will be valid for more 1 hour. Without this the token would expire in 30 minutes.
});
```

# Destroying the token

You can invalidate the token by calling ````destroy```` function. This will remove the key/value associated to the token from Redis.
All future calls to ````verify```` will throw ````JwtRedis.TokenExpiredError````.

```javascript
jwtRedis.destroy(token).then(() => {
  // The token was removed from Redis
});
```

# Promises

All functions will return a Promise. You can set the Promise implementation by passing the option ````promiseImpl```` when you instantiate a new ````JwtRedis````.

```javascript
const Promise = require('bluebird')
const jwtRedis = new JwtRedis(redis, {
  promiseImpl: Promise,
});
```

# API

Create a token
### jwtRedis.sign(payload, secretOrPrivateKey [, options]) ###

Verify the token
### jwtRedis.verify(token, secretOrPublicKey [, options]) ###

Decode the token
### jwt.decode(token [, options]) ###

Postpone the token expiration
### jwtRedis.touch(token) ###

Destroy the token
### jwtRedis.destroy(token) ###

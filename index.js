'use strict';

const biscuit = require('@biscuit-auth/biscuit-wasm')

module.exports = function(options) {
  const publicKey = biscuit.PublicKey.from_hex(options.publicKey)

  var middleware = function(req, res, next) {
    try {
      const authHeader = req.headers.authorization;

      var authorizer = new biscuit.Authorizer()

      console.log("created authorizer")
      if(options.policies !== undefined) {
        authorizer.add_code(options.policies)
        console.log("added code")
      }

      if(authHeader !== undefined) {
        const token = biscuit.Biscuit.from_base64(authHeader, publicKey)
        authorizer.add_token(token)
        console.log("added token")
      }

      if(options.extractor !== undefined) {
        console.log("will call extractor")
        options.extractor(req, authorizer)
      }

      console.log("will authorize")
      const res = authorizer.authorize()
      console.log("ok")
      next()
    } catch(error) {
      //console.log("not authorized: "+authorizer.print())
      console.log("error: "+JSON.stringify(error))
      return res.status(403).json({
        status: 403,
        message: 'FORBIDDEN'
      })
    }
  }

  return middleware;
};



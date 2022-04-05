# express-biscuit

Express authorization middleware using Biscuit tokens and policies

Example usage:

```javascript
const express = require('express')
const express_biscuit = require('@biscuit-auth/express-biscuit')
const {fact} = require('@biscuit-auth/express-biscuit')
const app = express()

const pubKey = "dfd559075dcf56c8c6777fbd3c553827dd51645bb8ee87a975a172980f8f16e5"

app.get('/user/:user_id',
  express_biscuit({
    // the root public key used to verify the signature
    publicKey: pubKey,
    // a list of static authorizer policies
    policies: "check if user(1); allow if true;",
    // the extractor method is used to get data from the request and
    // create authorizer facts from it
    extractor: function(req, authorizer) {
      authorizer.add_fact(
        // you can use template strings to create the facts, this prevents
        // injection issues when integrating user controlled data
        fact`user(${parseInt(req.params.user_id)})`
      )
    }
  }),
  function (req, res) {
    res.send('Hello '+req.params.user_id+"\n")
})
```
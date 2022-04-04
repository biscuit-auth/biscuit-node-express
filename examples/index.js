const express = require('express')
const express_biscuit = require('@biscuit-auth/express-biscuit')
const {fact} = require('@biscuit-auth/express-biscuit')
const biscuit = require('@biscuit-auth/biscuit-wasm')
const app = express()

const privKey = "5088cc9e13f7b1433e77dab0f998eb6eeaac5cb17e9ab074ecd71f4e36682d4b"
const pubKey = "dfd559075dcf56c8c6777fbd3c553827dd51645bb8ee87a975a172980f8f16e5"

app.get('/user/:user_id',
  express_biscuit({
    publicKey: pubKey,
    policies: "check if user(1); allow if true;",
    extractor: function(req, authorizer) {
      authorizer.add_fact(fact`user(${parseInt(req.params.user_id)})`)
    }
  }),
  function (req, res) {
  res.send('Hello '+req.params.user_id+"\n")
})

app.post('/register', function(req, res) {
  let builder = biscuit.Biscuit.builder()
  builder.add_authority_fact("user(1)");

  let privateKey = biscuit.PrivateKey.from_hex(privKey)
  let token = builder.build(privateKey)

  let encoded_token = token.to_base64()

  res.status(200).json({
    token: encoded_token
  })

})

app.listen(3000)

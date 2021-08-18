const ocsp = require('../')
const fixtures = require('./fixtures')

const assert = require('assert')

describe('OCSP Server', function () {
  const issuer = fixtures.certs.issuer
  const good = fixtures.certs.good
  const revoked = fixtures.certs.revoked

  let server
  after(function (cb) {
    server.close(cb)
  })

  it('should provide ocsp response to the client', function (cb) {
    server = ocsp.Server.create({
      cert: issuer.cert,
      key: issuer.key
    })

    server.addCert(43, 'good')
    server.addCert(44, 'revoked', {
      revocationTime: new Date(),
      revocationReason: 'cACompromise'
    })

    server.listen(8000, function () {
      ocsp.check({
        cert: good.cert,
        issuer: issuer.cert
      }, function (err, res) {
        if (err) { throw err }

        assert.strictEqual(res.certStatus.type, 'good')

        next()
      })
    })

    function next () {
      ocsp.check({
        cert: revoked.cert,
        issuer: issuer.cert
      }, function (err, res) {
        assert(err)
        assert.strictEqual(res.certStatus.type, 'revoked')
        cb()
      })
    }
  })
})

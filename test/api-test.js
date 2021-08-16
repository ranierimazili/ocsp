const ocsp = require('../')
const fixtures = require('./fixtures')

const assert = require('assert')
const https = require('https')

describe('OCSP Stapling Provider', function () {
  describe('.check()', function () {
    it('should validate google.com', function (cb) {
      ocsp.check({
        cert: fixtures.google,
        issuer: fixtures.googleIssuer
      }, function (err, res) {
        if (err) {
          throw err
        }

        assert.strictEqual(res.certStatus.type, 'good')
        cb()
      })
    })
  })

  describe('.verify()', function () {
    it('should verify reddit.com\'s stapling', function (cb) {
      try {
        const req = https.request({
          host: 'reddit.com',
          port: 443,
          requestOCSP: true
        }, function (res) {
          // Should not be called
          assert(false)
        })

        req.on('error', err => console.error(err))
        req.on('socket', function (socket) {
          socket.on('OCSPResponse', function (stapling) {
            onOCSPResponse(socket, stapling)
          })
        })

        function onOCSPResponse (socket, stapling) {
          const cert = socket.getPeerCertificate(true)

          const req = ocsp.request.generate(cert.raw, cert.issuerCertificate.raw)
          ocsp.verify({
            request: req,
            response: stapling
          }, function (err, res) {
            assert(!err)

            assert.strictEqual(res.certStatus.type, 'good')
            socket.destroy()
            cb()
          })
        }
      } catch (e) {
        console.log('IBA', e)
      }
    })
  })

  describe('.getOCSPURI()', function () {
    it('should work on cert without extensions', function (cb) {
      ocsp.getOCSPURI(fixtures.noExts, function (err) {
        assert(err)
        cb()
      })
    })
  })
})

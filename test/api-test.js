const ocsp = require('../')
const fixtures = require('./fixtures')

const assert = require('assert')
const https = require('https')
const tls = require('tls')
const net = require('net')

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
        const socket = new net.Socket()
        socket.setEncoding('utf8')

        socket.once('connect', () => {
          const client = tls.connect({
            host: 'reddit.com',
            port: 443,
            requestOCSP: true
          })

          client.on('OCSPResponse', function (stapling) {
            if (stapling) {
              const cert = client.getPeerCertificate(true)

              const req = ocsp.request.generate(cert.raw, cert.issuerCertificate.raw)
              ocsp.verify({ request: req, response: stapling }, function (err, res) {
                if (err) {
                  return cb(err)
                }
                assert.strictEqual(res.certStatus.type, 'good')
                socket.end(cb)
              })
            } else {
              cb(new Error('empty stapling'))
            }
          })
        })

        socket.connect(443, 'reddit.com')
      } catch (e) {
        cb(e)
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

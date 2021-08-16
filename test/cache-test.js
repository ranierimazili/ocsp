const ocsp = require('../')
const fixtures = require('./fixtures')

const assert = require('assert')
const https = require('https')

describe('OCSP Cache', function () {
  const issuer = fixtures.certs.issuer
  const good = fixtures.certs.good
  const revoked = fixtures.certs.revoked

  let server
  let agent
  beforeEach(function (cb) {
    server = ocsp.Server.create({
      cert: issuer.cert,
      key: issuer.key
    })

    server.addCert(43, 'good')
    server.addCert(44, 'revoked', {
      revocationTime: new Date(),
      revocationReason: 'CACompromise'
    })

    server.listen(8000, function () {
      cb()
    })

    agent = new ocsp.Agent()

    cache = new ocsp.Cache()
  })

  afterEach(function (cb) {
    server.close(cb)
    agent = null
  })

  it('should cache ocsp response', function (cb) {
    const httpServer = https.createServer({
      cert: good.cert + '\n' + good.issuer,
      key: good.key
    }, function (req, res) {
      res.end('hello world')
    })

    httpServer.on('OCSPRequest', function (cert, issuer, cb) {
      ocsp.getOCSPURI(cert, function (err, uri) {
        if (err) { return cb(err) }

        const req = ocsp.request.generate(cert,
          issuer || fixtures.certs.issuer.cert)
        const options = {
          url: uri,
          ocsp: req.data
        }

        cache.request(req.id, options, cb)
      })
    })

    httpServer.listen(8001, function () {
      https.get({
        agent: agent,
        ca: issuer.cert,
        rejectUnauthorized: !/^v0.12/.test(process.version),
        servername: 'local.host',
        port: 8001
      }, function (res) {
        cb()
      })
    })
  })
})

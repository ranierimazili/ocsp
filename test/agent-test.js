const ocsp = require('../')
const https = require('https')

describe('OCSP Agent', function () {
  // Retry all tests in this suite up to 4 times
  this.retries(4)

  let a
  beforeEach(function () {
    a = new ocsp.Agent()
  })

  const websites = [
    'www.google.com',
    'google.com',
    'helloworld.letsencrypt.org',
    'yahoo.com',
    'nytimes.com',
    'microsoft.com'
  ]

  websites.forEach(function (host) {
    it('should connect and validate ' + host, function (cb) {
      https.get({
        host: host,
        port: 443,
        agent: a
      }, function (res) {
        res.resume()
        cb()
      })
    })
  })
})

describe('OCSP Agent failed', function () {
  let a
  beforeEach(function () {
    a = new ocsp.Agent()
  })

  const websites = [
    'p.vj-vid.com',
    'vast.bp3861034.btrll.com',
    'revoked.badssl.com',
    'expired.badssl.com',
    'self-signed.badssl.com',
    'untrusted-root.badssl.com',
    'pinning-test.badssl.com', // this one is never caught curious why?
  ]

  websites.forEach(function (host) {
    it('should connect and emit error ' + host, function (cb) {
      https.get({
        host: host,
        port: 443,
        agent: a
      }).on('error', (e) => {
        cb()
      })
    })
  })
})

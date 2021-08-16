const ocsp = require('../')
const https = require('https')

describe('OCSP Agent', function () {
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
      const req = https.get({
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
    'vast.bp3861034.btrll.com'
  ]

  websites.forEach(function (host) {
    it('should connect and emit error ' + host, function (cb) {
      const req = https.get({
        host: host,
        port: 443,
        agent: a
      }).on('error', (e) => {
        cb()
      })
    })
  })
})

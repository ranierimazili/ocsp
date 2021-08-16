const ocsp = require('../')
const fixtures = require('./fixtures')

const assert = require('assert')
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

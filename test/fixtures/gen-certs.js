#!/usr/bin/env node

const fs = require('fs')
const path = require('path')
const fixtures = require('../fixtures')

const options = {
  serial: 42,
  commonName: 'mega.ca',
  size: 2048
}

fixtures.getOCSPCert(options, function (cert, key) {
  fs.writeFileSync(path.join(__dirname, 'issuer-cert.pem'), cert)
  fs.writeFileSync(path.join(__dirname, ' issuer-key.pem'), key)

  const options = {
    issuer: cert,
    issuerKey: key,
    serial: 43,
    size: 2048
  }

  fixtures.getOCSPCert(options, function (cert, key) {
    fs.writeFileSync(path.join(__dirname, 'good-cert.pem'), cert)
    fs.writeFileSync(path.join(__dirname, 'good-key.pem'), key)

    options.serial++
    fixtures.getOCSPCert(options, function (cert, key) {
      fs.writeFileSync(path.join(__dirname, 'revoked-cert.pem'), cert)
      fs.writeFileSync(path.join(__dirname, 'revoked-key.pem'), key)
    })
  })
})

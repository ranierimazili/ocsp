const ocsp = require('../../')

const https = require('https')
const fs = require('fs')
const path = require('path')
const rfc2560 = require('asn1.js-rfc2560')
const rfc5280 = require('asn1.js-rfc5280')
const keyGen = require('selfsigned.js').create()

/*
   AuthorityInfoAccessSyntax  ::=
           SEQUENCE SIZE (1..MAX) OF AccessDescription

   AccessDescription  ::=  SEQUENCE {
           accessMethod          OBJECT IDENTIFIER,
           accessLocation        GeneralName  }
 */

const googleOptions = {
  hostname: 'google.com',
  port: 443,
  path: '/',
  method: 'GET',
  headers: {
    'User-Agent': 'Node.js/https'
  }
}

const req = https.request(googleOptions, res => {
  res.on('data', d => { })
})
  .on('error', e => {
    console.error(e)
  })

req.on('socket', socket => {
  socket.on('secureConnect', () => {
    const googleCerts = socket.getPeerCertificate(true)
    exports.google = '-----BEGIN CERTIFICATE-----\n' + googleCerts.raw.toString('base64') + '\n-----END CERTIFICATE-----'
    exports.googleIssuer ='-----BEGIN CERTIFICATE-----\n' + googleCerts.issuerCertificate.raw.toString('base64') + '\n-----END CERTIFICATE-----'
  })
})

req.end()

exports.noExts = fs.readFileSync(path.join(__dirname, 'no-exts-cert.pem'))

exports.certs = {};

['issuer', 'good', 'revoked'].forEach(function (name) {
  exports.certs[name] = {
    cert: fs.readFileSync(path.join(__dirname, name + '-cert.pem')),
    key: fs.readFileSync(path.join(__dirname, name + '-key.pem'))
  }
})

exports.getOCSPCert = function getOCSPCert (options, cb) {
  if (!options) { options = {} }

  const size = options.size || 256
  const commonName = options.commonName || 'local.host'
  const OCSPEndPoint = options.OCSPEndPoint || 'http://127.0.0.1:8000/ocsp'

  let issuer = options.issuer
  if (issuer) { issuer = ocsp.utils.toDER(issuer, 'CERTIFICATE') }
  if (issuer) { issuer = rfc5280.Certificate.decode(issuer, 'der') }

  let issuerKeyData = options.issuerKey

  if (issuerKeyData) { issuerKeyData = ocsp.utils.toDER(options.issuerKey, 'RSA PRIVATE KEY') }

  if (issuerKeyData) { issuerKeyData = ocsp.utils.RSAPrivateKey.decode(issuerKeyData, 'der') } else { issuerKeyData = options.issuerKeyData }

  function getPrime (cb) {
    keyGen.getPrime(size >> 1, function (err, prime) {
      if (err) { return getPrime(cb) }

      cb(prime)
    })
  }

  function getTwoPrimes (cb) {
    const primes = []
    getPrime(done)
    getPrime(done)

    function done (prime) {
      primes.push(prime)
      if (primes.length === 2) { return cb(primes[0], primes[1]) }
    }
  }

  function getKeyData (cb) {
    getTwoPrimes(function (p, q) {
      const keyData = keyGen.getKeyData(p, q)
      if (!keyData) { return getKeyData(cb) }

      cb(keyData)
    })
  }

  const ext = rfc5280.AuthorityInfoAccessSyntax.encode([{
    accessMethod: rfc2560['id-pkix-ocsp'],
    accessLocation: {
      type: 'uniformResourceIdentifier',
      value: OCSPEndPoint
    }
  }], 'der')

  getKeyData(function (keyData) {
    const certData = keyGen.getCertData({
      serial: options.serial,
      keyData,
      commonName,
      issuer,
      issuerKeyData,
      extensions: [{
        extnID: [1, 3, 6, 1, 5, 5, 7, 1, 1], // rfc5280['id-pe-authorityInfoAccess'],
        critical: false,
        extnValue: ext
      }]
    })

    const pem = keyGen.getCert(certData, 'pem')
    return cb(pem, keyGen.getPrivate(keyData, 'pem'))
  })
}

# Test dependencies
cwd = process.cwd()
fs = require 'fs'
path = require 'path'
sinon = require 'sinon'
mkdirp = require 'mkdirp'
rimraf = require 'rimraf'
base64url = require 'base64url'
chai = require 'chai'
sinonChai = require 'sinon-chai'
expect = chai.expect

# Configure Chai and Sinon
chai.use sinonChai
chai.should()

# Module to be tested
AnvilConnectKeys = require path.join cwd, 'keys'

fsExists = (path) ->
  try
    fs.lstatSync(path)
    return true
  catch e
    if e.code == 'ENOENT'
      return false
    else
      throw e

fileExists = (path) ->
  try
    return fs.lstatSync(path).isFile()
  catch e
    if e.code == 'ENOENT'
      return false
    else
      throw e

dirExists = (path) ->
  try
    return fs.lstatSync(path).isDirectory()
  catch e
    if e.code == 'ENOENT'
      return false
    else
      throw e

# Tests

describe 'AnvilConnectKeys', ->

  before ->
    if dirExists(path.join cwd, 'tmp')
      rimraf.sync(path.join cwd, 'tmp')
    mkdirp.sync path.join cwd, 'tmp'

  describe 'constructor', ->

    describe 'with valid folder', ->
      {connectKeys} = {}

      before ->
        connectKeys = new AnvilConnectKeys path.join cwd, 'tmp'

      it 'should use the keys directory in the given folder', ->
        connectKeys.directory.should.equal path.join cwd, 'tmp', 'keys'

      it 'should set public signature key path in the same directory', ->
        connectKeys.sig.pub.should.equal path.join cwd, 'tmp', 'keys', 'sig.rsa.pub.pem'

      it 'should set private signature key path in the same directory', ->
        connectKeys.sig.prv.should.equal path.join cwd, 'tmp', 'keys', 'sig.rsa.prv.pem'

      it 'should set public encryption key path in the same directory', ->
        connectKeys.enc.pub.should.equal path.join cwd, 'tmp', 'keys', 'enc.rsa.pub.pem'

      it 'should set private encryption key path in the same directory', ->
        connectKeys.enc.prv.should.equal path.join cwd, 'tmp', 'keys', 'enc.rsa.prv.pem'

      it 'should set setup token path in the same directory', ->
        connectKeys.setup.should.equal path.join cwd, 'tmp', 'keys', 'setup.token'

    describe 'with no folder', ->
      {connectKeys} = {}

      before ->
        connectKeys = new AnvilConnectKeys

      it 'should use the keys directory in the current folder', ->
        connectKeys.directory.should.equal path.join cwd, 'keys'

      it 'should set public signature key path in the same directory', ->
        connectKeys.sig.pub.should.equal path.join cwd, 'keys', 'sig.rsa.pub.pem'

      it 'should set private signature key path in the same directory', ->
        connectKeys.sig.prv.should.equal path.join cwd, 'keys', 'sig.rsa.prv.pem'

      it 'should set public encryption key path in the same directory', ->
        connectKeys.enc.pub.should.equal path.join cwd, 'keys', 'enc.rsa.pub.pem'

      it 'should set private encryption key path in the same directory', ->
        connectKeys.enc.prv.should.equal path.join cwd, 'keys', 'enc.rsa.prv.pem'

      it 'should set setup token path in the same directory', ->
        connectKeys.setup.should.equal path.join cwd, 'keys', 'setup.token'

  describe 'generate key pair', ->
    this.timeout(5000)

    before ->
      AnvilConnectKeys.generateKeyPair(
        path.join cwd, 'tmp', 'pub', 'public.key'
        path.join cwd, 'tmp', 'prv', 'private.key'
      )

    it 'should create the public key folder if needed', ->
      expect(dirExists(path.join cwd, 'tmp', 'pub')).to.be.true

    it 'should create the private key folder if needed', ->
      expect(dirExists(path.join cwd, 'tmp', 'prv')).to.be.true

    it 'should generate a private key', ->
      expect(fileExists(path.join cwd, 'tmp', 'prv', 'private.key')).to.be.true

    it 'should generate a public key', ->
      expect(fileExists(path.join cwd, 'tmp', 'pub', 'public.key')).to.be.true

  describe 'generate key pairs', ->
    this.timeout(10000)

    before ->
      connectKeys = new AnvilConnectKeys path.join cwd, 'tmp'
      connectKeys.generateKeyPairs()

    it 'should generate public signing key', ->
      expect(
        fileExists(path.join cwd, 'tmp', 'keys', 'sig.rsa.pub.pem')
      ).to.be.true

    it 'should generate private signing key', ->
      expect(
        fileExists(path.join cwd, 'tmp', 'keys', 'sig.rsa.prv.pem')
      ).to.be.true

    it 'should generate public encryption key', ->
      expect(
        fileExists(path.join cwd, 'tmp', 'keys', 'enc.rsa.pub.pem')
      ).to.be.true

    it 'should generate private encryption key', ->
      expect(
        fileExists(path.join cwd, 'tmp', 'keys', 'enc.rsa.prv.pem')
      ).to.be.true

  describe 'load key pair', ->
    {keys} = {}

    before ->
      keys = AnvilConnectKeys.loadKeyPair(
        path.join cwd, 'tmp', 'pub', 'public.key'
        path.join cwd, 'tmp', 'prv', 'private.key'
        'sig'
      )

    it 'should return the PEM public key', ->
      keys.pem.pub.should.contain 'BEGIN PUBLIC KEY'

    it 'should return the PEM private key', ->
      keys.pem.prv.should.contain 'BEGIN RSA PRIVATE KEY'

    it 'should return the public key as a JWK', ->
      keys.jwk.pub.kty.should.equal 'RSA'
      keys.jwk.pub.use.should.equal 'sig'
      keys.jwk.pub.alg.should.equal 'RS256'
      keys.jwk.pub.e.should.equal 'AQAB'
      expect(base64url.toBuffer(keys.jwk.pub.n).length).to.equal 512

    it 'should not return the private key as a JWK', ->
      expect(keys.jwk.prv).to.not.be.ok

  describe 'load key pairs', ->
    {keys} = {}

    before ->
      connectKeys = new AnvilConnectKeys path.join cwd, 'tmp'
      keys = connectKeys.loadKeyPairs()

    it 'should return the PEM public signing key', ->
      keys.sig.pub.should.contain 'BEGIN PUBLIC KEY'

    it 'should return the PEM private signing key', ->
      keys.sig.prv.should.contain 'BEGIN RSA PRIVATE KEY'

    it 'should return the PEM public encryption key', ->
      keys.enc.pub.should.contain 'BEGIN PUBLIC KEY'

    it 'should return the PEM private encryption key', ->
      keys.enc.prv.should.contain 'BEGIN RSA PRIVATE KEY'

    it 'should only return two JWKs', ->
      keys.jwks.keys.length.should.equal 2

    it 'should return the JWK public signing key', ->
      keys.jwks.keys[0].kty.should.equal 'RSA'
      keys.jwks.keys[0].use.should.equal 'sig'
      keys.jwks.keys[0].alg.should.equal 'RS256'
      keys.jwks.keys[0].e.should.equal 'AQAB'
      expect(base64url.toBuffer(keys.jwks.keys[0].n).length).to.equal 512

    it 'should return the JWK public encryption key', ->
      keys.jwks.keys[1].kty.should.equal 'RSA'
      keys.jwks.keys[1].use.should.equal 'enc'
      keys.jwks.keys[1].alg.should.equal 'RS256'
      keys.jwks.keys[1].e.should.equal 'AQAB'
      expect(base64url.toBuffer(keys.jwks.keys[1].n).length).to.equal 512

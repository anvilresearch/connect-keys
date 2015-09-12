# Test dependencies
cwd = process.cwd()
fs = require 'fs'
path = require 'path'
sinon = require 'sinon'
crypto = require 'crypto'
mkdirp = require 'mkdirp'
childProcess = require 'child_process'
pemjwk = require 'pem-jwk'
chai = require 'chai'
sinonChai = require 'sinon-chai'
expect = chai.expect

# Configure Chai and Sinon
chai.use sinonChai
chai.should()

# Module to be tested
AnvilConnectKeys = require path.join cwd, 'keys'

# Tests

describe 'AnvilConnectKeys', ->

  describe 'constructor', ->

    describe 'with valid folder', ->
      {connectKeys} = {}

      before ->
        connectKeys = new AnvilConnectKeys '/test'

      it 'should use the keys directory in the given folder', ->
        connectKeys.directory.should.equal '/test/keys'

      it 'should set public signature key path in the same directory', ->
        connectKeys.sig.pub.should.equal '/test/keys/sig.rsa.pub.pem'

      it 'should set private signature key path in the same directory', ->
        connectKeys.sig.prv.should.equal '/test/keys/sig.rsa.prv.pem'

      it 'should set public encryption key path in the same directory', ->
        connectKeys.enc.pub.should.equal '/test/keys/enc.rsa.pub.pem'

      it 'should set private encryption key path in the same directory', ->
        connectKeys.enc.prv.should.equal '/test/keys/enc.rsa.prv.pem'

      it 'should set setup token path in the same directory', ->
        connectKeys.setup.should.equal '/test/keys/setup.token'

    describe 'with no folder', ->
      {connectKeys} = {}

      before ->
        sinon.stub process, 'cwd', -> '/cwd'
        connectKeys = new AnvilConnectKeys

      after ->
        process.cwd.restore()

      it 'should use the keys directory in the current folder', ->
        connectKeys.directory.should.equal '/cwd/keys'

      it 'should set public signature key path in the same directory', ->
        connectKeys.sig.pub.should.equal '/cwd/keys/sig.rsa.pub.pem'

      it 'should set private signature key path in the same directory', ->
        connectKeys.sig.prv.should.equal '/cwd/keys/sig.rsa.prv.pem'

      it 'should set public encryption key path in the same directory', ->
        connectKeys.enc.pub.should.equal '/cwd/keys/enc.rsa.pub.pem'

      it 'should set private encryption key path in the same directory', ->
        connectKeys.enc.prv.should.equal '/cwd/keys/enc.rsa.prv.pem'

      it 'should set setup token path in the same directory', ->
        connectKeys.setup.should.equal '/cwd/keys/setup.token'

  describe 'generate key pair', ->

    describe 'with sufficient access rights and valid paths', ->

      before ->
        sinon.stub mkdirp, 'sync'
        sinon.stub childProcess, 'execFileSync'
        AnvilConnectKeys.generateKeyPair '/pub/public.key', '/prv/private.key'

      after ->
        mkdirp.sync.restore()
        childProcess.execFileSync.restore()

      it 'should create the public key folder if needed', ->
        mkdirp.sync.should.have.been.calledWith '/pub'

      it 'should create the private key folder if needed', ->
        mkdirp.sync.should.have.been.calledWith '/prv'

      it 'should call OpenSSL to generate a 4096-bit RSA private key', ->
        childProcess.execFileSync.should.have.been.calledWith(
          'openssl', [ 'genrsa', '-out', '/prv/private.key', '4096']
        )

      it 'should call OpenSSL to generate an RSA public key', ->
        childProcess.execFileSync.should.have.been.calledWith(
          'openssl', [
            'rsa', '-pubout', '-in', '/prv/private.key',
            '-out', '/pub/public.key'
          ]
        )

    describe 'with insufficient access rights to create paths', ->
      {err} = {}

      before ->
        sinon.stub(mkdirp, 'sync').throws()
        sinon.stub childProcess, 'execFileSync'
        try
          AnvilConnectKeys.generateKeyPair '/pub/public.key', '/prv/private.key'
        catch e
          err = e

      after ->
        mkdirp.sync.restore()
        childProcess.execFileSync.restore()

      it 'should throw an error', ->
        err.should.be.instanceof Error

      it 'should not call OpenSSL', ->
        childProcess.execFileSync.should.not.have.been.called

    describe 'with error during OpenSSL execution', ->
      {err} = {}

      before ->
        sinon.stub mkdirp, 'sync'
        sinon.stub(childProcess, 'execFileSync').throws()
        try
          AnvilConnectKeys.generateKeyPair '/pub/public.key', '/prv/private.key'
        catch e
          err = e

      after ->
        mkdirp.sync.restore()
        childProcess.execFileSync.restore()

      it 'should throw an error', ->
        err.should.be.instanceof Error

  describe 'generate key pairs', ->

    describe 'with no errors during keypair generation', ->

      before ->
        sinon.stub AnvilConnectKeys, 'generateKeyPair'
        connectKeys = new AnvilConnectKeys '/test'
        connectKeys.generateKeyPairs()

      after ->
        AnvilConnectKeys.generateKeyPair.restore()

      it 'should generate signing key pairs', ->
        AnvilConnectKeys.generateKeyPair.should.have.been.calledWith(
          '/test/keys/sig.rsa.pub.pem', '/test/keys/sig.rsa.prv.pem'
        )

      it 'should generate encryption key pairs', ->
        AnvilConnectKeys.generateKeyPair.should.have.been.calledWith(
          '/test/keys/enc.rsa.pub.pem', '/test/keys/enc.rsa.prv.pem'
        )

    describe 'with errors during keypair generation', ->

      {err} = {}

      before ->
        sinon.stub(AnvilConnectKeys, 'generateKeyPair').throws()
        connectKeys = new AnvilConnectKeys '/test'
        try
          connectKeys.generateKeyPairs()
        catch e
          err = e

      after ->
        AnvilConnectKeys.generateKeyPair.restore()

      it 'should not trap the error', ->
        err.should.be.an.instanceof Error

  describe 'load key pair', ->

    describe 'with sufficient access rights and valid keys', ->
      {keys} = {}

      before ->
        sinon.stub fs, 'readFileSync', (path) ->
          switch path
            when '/pub/public.key' then 'PUBLIC PEM'
            when '/prv/private.key' then 'PRIVATE PEM'
        sinon.stub pemjwk, 'pem2jwk', (key) ->
          switch key
            when 'PUBLIC PEM'
              kty: 'PUBLIC JWK'
              n: 1
              e: 2
            when 'PRIVATE PEM'
              kty: 'PRIVATE JWK'
              n: 3
              e: 4
        keys = AnvilConnectKeys.loadKeyPair(
          '/pub/public.key', '/prv/private.key', 'sig'
        )

      after ->
        fs.readFileSync.restore()
        pemjwk.pem2jwk.restore()

      it 'should return the public key', ->
        keys.pem.pub.should.equal 'PUBLIC PEM'

      it 'should return the private key', ->
        keys.pem.prv.should.equal 'PRIVATE PEM'

      it 'should return the public key as a JWK', ->
        keys.jwk.pub.should.eql
          kty: 'PUBLIC JWK'
          use: 'sig'
          alg: 'RS256'
          n: 1
          e: 2

      it 'should not return the private key as a JWK', ->
        expect(keys.jwk.prv).to.not.be.ok

    describe 'with insufficient access rights', ->
      {err} = {}

      before ->
        sinon.stub(fs, 'readFileSync').throws()
        sinon.stub pemjwk, 'pem2jwk'
        try
          AnvilConnectKeys.loadKeyPair(
            '/pub/public.key', '/prv/private.key', 'sig'
          )
        catch e
          err = e

      after ->
        fs.readFileSync.restore()
        pemjwk.pem2jwk.restore()

      it 'should throw an error', ->
        err.should.be.an.instanceof Error

    describe 'with an invalid key', ->
      {err} = {}

      before ->
        sinon.stub fs, 'readFileSync'
        sinon.stub(pemjwk, 'pem2jwk').throws()
        try
          AnvilConnectKeys.loadKeyPair(
            '/pub/public.key', '/prv/private.key', 'sig'
          )
        catch e
          err = e

      after ->
        fs.readFileSync.restore()
        pemjwk.pem2jwk.restore()

      it 'should throw an error', ->
        err.should.be.an.instanceof Error

  describe 'load key pairs', ->

    describe 'with no errors during key pair loading', ->
      {keys} = {}

      before ->
        sinon.stub AnvilConnectKeys, 'loadKeyPair', (pub, prv, use) ->
          switch
            when pub == '/test/keys/sig.rsa.pub.pem' && \
            prv == '/test/keys/sig.rsa.prv.pem' && use == 'sig'
              pem:
                pub: 'PUBLIC SIGNING PEM'
                prv: 'PRIVATE SIGNING PEM'
              jwk:
                pub:
                  kty: 'PUBLIC SIGNING JWK'
                  use: 'sig'
                  alg: 'RS256'
                  n: 1
                  e: 2
            when pub == '/test/keys/enc.rsa.pub.pem' && \
            prv == '/test/keys/enc.rsa.prv.pem' && use == 'enc'
              pem:
                pub: 'PUBLIC ENCRYPTION PEM'
                prv: 'PRIVATE ENCRYPTION PEM'
              jwk:
                pub:
                  kty: 'PUBLIC ENCRYPTION JWK'
                  use: 'enc'
                  alg: 'RS256'
                  n: 3
                  e: 4
        connectKeys = new AnvilConnectKeys '/test'
        keys = connectKeys.loadKeyPairs()

      it 'should return the PEM public signing key', ->
        keys.sig.pub.should.equal 'PUBLIC SIGNING PEM'

      it 'should return the PEM private signing key', ->
        keys.sig.prv.should.equal 'PRIVATE SIGNING PEM'

      it 'should return the PEM public encryption key', ->
        keys.enc.pub.should.equal 'PUBLIC ENCRYPTION PEM'

      it 'should return the PEM private encryption key', ->
        keys.enc.prv.should.equal 'PRIVATE ENCRYPTION PEM'

      it 'should only return two JWKs', ->
        keys.jwks.keys.length.should.equal 2

      it 'should return the JWK public signing key', ->
        keys.jwks.keys.should.contain
          kty: 'PUBLIC SIGNING JWK'
          use: 'sig'
          alg: 'RS256'
          n: 1
          e: 2

      it 'should return the JWK public encryption key', ->
        keys.jwks.keys.should.contain
          kty: 'PUBLIC ENCRYPTION JWK'
          use: 'enc'
          alg: 'RS256'
          n: 3
          e: 4

  describe 'generate setup token (static)', ->

    describe 'with sufficient access rights', ->
      {token} = {}

      before ->
        sinon.stub mkdirp, 'sync'
        sinon.stub fs, 'writeFileSync'
        sinon.stub crypto, 'randomBytes', -> 'SETUP TOKEN'
        token = AnvilConnectKeys.generateSetupToken '/test/setup.token'

      after ->
        mkdirp.sync.restore()
        fs.writeFileSync.restore()
        crypto.randomBytes.restore()

      it 'should create the key folder if needed', ->
        mkdirp.sync.should.have.been.calledWith '/test'

      it 'should generate a 256-byte random token', ->
        crypto.randomBytes.should.have.been.calledWith 256

      it 'should save the token', ->
        fs.writeFileSync.should.have.been.calledWith(
          '/test/setup.token', 'SETUP TOKEN', 'utf8'
        )

      it 'should return the token', ->
        token.should.equal 'SETUP TOKEN'

    describe 'with insufficient access rights', ->
      {err} = {}

      before ->
        sinon.stub(mkdirp, 'sync').throws()
        sinon.stub fs, 'writeFileSync'
        sinon.stub crypto, 'randomBytes', -> 'SETUP TOKEN'
        try
          token = AnvilConnectKeys.generateSetupToken '/test/setup.token'
        catch e
          err = e

      after ->
        mkdirp.sync.restore()
        fs.writeFileSync.restore()
        crypto.randomBytes.restore()

      it 'should throw an error', ->
        err.should.be.an.instanceof Error

  describe 'load setup token (static)', ->

    describe 'with sufficient access rights', ->
      {token} = {}

      before ->
        sinon.stub fs, 'readFileSync', -> 'SETUP TOKEN'
        token = AnvilConnectKeys.loadSetupToken '/test/setup.token'

      after ->
        fs.readFileSync.restore()

      it 'should load the token', ->
        fs.readFileSync.should.have.been.calledWith '/test/setup.token', 'utf8'

      it 'should return the token', ->
        token.should.equal 'SETUP TOKEN'

    describe 'with insufficient access rights', ->
      {err} = {}

      before ->
        sinon.stub(mkdirp, 'sync').throws()
        sinon.stub fs, 'readFileSync'
        try
          token = AnvilConnectKeys.readFileSync '/test/setup.token'
        catch e
          err = e

      after ->
        mkdirp.sync.restore()
        fs.readFileSync.restore()

      it 'should throw an error', ->
        err.should.be.an.instanceof Error

  describe 'generate setup token (instance)', ->

    describe 'with no errors during token generation', ->
      {token} = {}

      before ->
        sinon.stub AnvilConnectKeys, 'generateSetupToken', -> 'SETUP TOKEN'
        connectKeys = new AnvilConnectKeys '/test'
        token = connectKeys.generateSetupToken()

      after ->
        AnvilConnectKeys.generateSetupToken.restore()

      it 'should generate a token', ->
        AnvilConnectKeys.generateSetupToken.should.have.been.calledWith(
          '/test/keys/setup.token'
        )

      it 'should return the token', ->
        token.should.equal 'SETUP TOKEN'

    describe 'with errors during token generation', ->
      {err} = {}

      before ->
        sinon.stub(AnvilConnectKeys, 'generateSetupToken').throws()
        connectKeys = new AnvilConnectKeys '/test'
        try
          token = connectKeys.generateSetupToken()
        catch e
          err = e

      after ->
        AnvilConnectKeys.generateSetupToken.restore()

      it 'should not trap the error', ->
        err.should.be.an.instanceof Error

  describe 'load setup token (instance)', ->

    describe 'with sufficient access rights', ->
      {token} = {}

      before ->
        sinon.stub AnvilConnectKeys, 'loadSetupToken', -> 'SETUP TOKEN'
        connectKeys = new AnvilConnectKeys '/test'
        token = connectKeys.loadSetupToken()

      after ->
        AnvilConnectKeys.loadSetupToken.restore()

      it 'should load the token', ->
        AnvilConnectKeys.loadSetupToken.should.have.been.calledWith(
          '/test/keys/setup.token'
        )

      it 'should return the token', ->
        token.should.equal 'SETUP TOKEN'

    describe 'with errors during token loading', ->
      {err} = {}

      before ->
        sinon.stub(AnvilConnectKeys, 'loadSetupToken').throws()
        connectKeys = new AnvilConnectKeys '/test'
        try
          token = connectKeys.loadSetupToken()
        catch e
          err = e

      after ->
        AnvilConnectKeys.loadSetupToken.restore()

      it 'should not trap the error', ->
        err.should.be.an.instanceof Error

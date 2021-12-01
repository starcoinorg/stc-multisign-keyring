const EventEmitter = require('events').EventEmitter
const Wallet = require('@starcoin/stc-wallet')
const arrayify = require('@ethersproject/bytes').arrayify
const stcUtil = require('@starcoin/stc-util')
const { utils, encoding } = require('@starcoin/starcoin')
const sigUtil = require('eth-sig-util')

const type = 'Multi Sign'
class MutiSignKeyring extends EventEmitter {

  /* PUBLIC METHODS */

  constructor(opts) {
    super()
    this.type = type
    this.wallets = []
    this.accounts = {}
    this.deserialize(opts)
  }

  serialize() {
    return Promise.resolve(Object.keys(this.accounts).map(k => {
      const account = this.accounts[k];
      return { address: k, ...account };
    }))
  }

  deserialize(keyPairs = []) {
    return new Promise((resolve, reject) => {
      try {
        keyPairs.forEach(({ address, privateKeys, publicKeys, thresHold }) => {
          this.accounts[address] = { privateKeys, publicKeys, thresHold }
        })
      } catch (e) {
        reject(e)
      }
      resolve()
    })
  }

  addAccounts(params) {
    const { publicKeys = [], privateKeys = [], thresHold = 1 } = params
    // console.log({ publicKeys, privateKeys, thresHold })
    return new Promise((resolve, reject) => {
      try {
        utils.multiSign
          .createMultiEd25519KeyShard(publicKeys, privateKeys, thresHold)
          .then((shard) => {
            // console.log({ shard })
            const address = utils.account.getMultiEd25519AccountAddress(shard);
            if (Object.keys(this.accounts).includes(address)) {
              reject(new Error('address already exists'))
            }
            this.accounts[address] = { publicKeys, privateKeys, thresHold };
            return resolve(Object.keys(this.accounts))
          });

      } catch (e) {
        log.Error(e)
        reject(e)
      }
    })
  }

  getAccounts() {
    console.log(this.accounts)
    return Promise.resolve(Object.keys(this.accounts))
  }

  // tx is rawUserTransaction.
  signTransaction(address, tx, opts = {}) {
    const privKey = this.getPrivateKeyFor(address, opts);
    const privKeyStr = stcUtil.addHexPrefix(privKey.toString('hex'))
    const hex = utils.tx.signRawUserTransaction(
      privKeyStr,
      tx,
    )
    return Promise.resolve(hex)
  }

  // For eth_sign, we need to sign arbitrary data:
  signMessage(address, data, opts = {}) {
    const message = stcUtil.stripHexPrefix(data)
    const privKey = this.getPrivateKeyFor(address, opts);
    var msgSig = stcUtil.ecsign(Buffer.from(message, 'hex'), privKey)
    var rawMsgSig = stcUtil.bufferToHex(sigUtil.concatSig(msgSig.v, msgSig.r, msgSig.s))
    return Promise.resolve(rawMsgSig)
  }

  // For eth_sign, we need to sign transactions:
  newGethSignMessage(withAccount, msgHex, opts = {}) {
    const privKey = this.getPrivateKeyFor(withAccount, opts);
    const msgBuffer = stcUtil.toBuffer(msgHex)
    const msgHash = stcUtil.hashPersonalMessage(msgBuffer)
    const msgSig = stcUtil.ecsign(msgHash, privKey)
    const rawMsgSig = stcUtil.bufferToHex(sigUtil.concatSig(msgSig.v, msgSig.r, msgSig.s))
    return Promise.resolve(rawMsgSig)
  }

  // For personal_sign, we need to prefix the message:
  signPersonalMessage(address, message, opts = {}) {
    const privKey = this.getPrivateKeyFor(address, opts);
    return utils.signedMessage.signMessage(message, privKey.toString('hex'))
      .then((payload) => {
        // const { publicKey, signature } = payload
        return payload
      })
  }

  // For stc_decrypt:
  decryptMessage(withAccount, encryptedData, opts) {
    const wallet = this._getWalletForAccount(withAccount, opts)
    const privKey = stcUtil.stripHexPrefix(wallet.getPrivateKey())
    const sig = sigUtil.decrypt(encryptedData, privKey)
    return Promise.resolve(sig)
  }

  // personal_signTypedData, signs data along with the schema
  signTypedData(withAccount, typedData, opts = { version: 'V1' }) {
    switch (opts.version) {
      case 'V1':
        return this.signTypedData_v1(withAccount, typedData, opts);
      case 'V3':
        return this.signTypedData_v3(withAccount, typedData, opts);
      case 'V4':
        return this.signTypedData_v4(withAccount, typedData, opts);
      default:
        return this.signTypedData_v1(withAccount, typedData, opts);
    }
  }

  // personal_signTypedData, signs data along with the schema
  signTypedData_v1(withAccount, typedData, opts = {}) {
    const privKey = this.getPrivateKeyFor(withAccount, opts);
    const sig = sigUtil.signTypedDataLegacy(privKey, { data: typedData })
    return Promise.resolve(sig)
  }

  // personal_signTypedData, signs data along with the schema
  signTypedData_v3(withAccount, typedData, opts = {}) {
    const privKey = this.getPrivateKeyFor(withAccount, opts);
    const sig = sigUtil.signTypedData(privKey, { data: typedData })
    return Promise.resolve(sig)
  }

  // personal_signTypedData, signs data along with the schema
  signTypedData_v4(withAccount, typedData, opts = {}) {
    const privKey = this.getPrivateKeyFor(withAccount, opts);
    const sig = sigUtil.signTypedData_v4(privKey, { data: typedData })
    return Promise.resolve(sig)
  }

  // get public key for nacl
  getEncryptionPublicKey(withAccount, opts = {}) {
    const privKey = this.getPrivateKeyFor(withAccount, opts);
    const publicKey = sigUtil.getEncryptionPublicKey(privKey)
    return Promise.resolve(publicKey)
  }

  // get public key
  getPublicKeyFor(address) {
    return this._getShardForAddress(address).then(shard => utils.account.getMultiEd25519AccountPublicKey(shard))
  }

  // returns an address specific to an app
  getAppKeyAddress(address, origin) {
    return new Promise((resolve, reject) => {
      try {
        const wallet = this._getWalletForAccount(address, {
          withAppKeyOrigin: origin,
        })
        const appKeyAddress = sigUtil.normalize(wallet.getAddress().toString('hex'))
        return resolve(appKeyAddress)
      } catch (e) {
        return reject(e)
      }
    })
  }

  // exportAccount should return a hex-encoded private key:
  exportAccount(address) {
    return this._getShardForAddress(address).then(shard => utils.account.getMultiEd25519AccountPrivateKey(shard))
  }

  removeAccount(address) {
    if (!this.wallets.map(w => stcUtil.bufferToHex(w.getAddress()).toLowerCase()).includes(address.toLowerCase())) {
      throw new Error(`Address ${address} not found in this keyring`)
    }
    this.wallets = this.wallets.filter(w => stcUtil.bufferToHex(w.getAddress()).toLowerCase() !== address.toLowerCase())
  }

  getReceiptIdentifier(address) {
    return this._getShardForAddress(address).then(shard => utils.account.getMultiEd25519AccountReceiptIdentifier(shard))
  }

  /* PRIVATE METHODS */

  _getShardForAddress(address) {
    const _address = sigUtil.normalize(address)
    return new Promise((resolve, reject) => {
      const account = this.accounts[_address]
      if (!account) {
        reject(new Error('MultiSign Keyring - Unable to find matching address.'))
      }
      try {
        utils.multiSign
          .createMultiEd25519KeyShard(account.publicKeys, account.privateKeys, account.thresHold)
          .then((shard) => {
            return resolve(shard)
          });
      } catch (e) {
        reject(e)
      }
    })
  }
}

MutiSignKeyring.type = type
module.exports = MutiSignKeyring

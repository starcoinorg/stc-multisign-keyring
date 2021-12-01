const assert = require('assert')
const ethUtil = require('ethereumjs-util')
const sigUtil = require('eth-sig-util')
const MutiSignKeyring = require('../')
const EthereumTx = require('ethereumjs-tx').Transaction
const { expect } = require('chai')

const TYPE_STR = 'Multi Sign'

// Sample account:
// const testAccount = {
//   key: '0xb8a9c05beeedb25df85f8d641538cbffedf67216048de9c678ee26260eb91952',
//   address: '0x01560cd3bac62cc6d7e6380600d9317363400896',
// }

const testAccount = {
  privateKey: '0x33bedc6650a622a3223c0ca391cb2bfe6078a2b254c08fa492ffe334e8c8ac1f',
  publicKey: '0x94c3732e3c08eee7738d33b4e6f74daa615da14a94607ac00b531d189cb5b0dd',
  address: '0x621500bf2b4aad17a690cb24f9a225c6',
  receiptIdentifier: 'stc1pvg2sp0etf2k30f5sevj0ng39cmhuvhh4vzevdu07ksg38r0mrd0xy9gqhu454tgh56gvkf8e5gjuv6hqjnv'
}


// Implemention of multi sign in https://starcoin.org/zh/developer/cli/multisig_account/
const thresHold = 2;

const alice = {
  'address': '0xd597bcfa4d3464b98bea990ce21aca06',
  'public_key': '0x547c6a1ef36e9e99865ce7ac028ee79aff404d279b568272bc7154802d4856bb',
  'private_key': '0xa9e47d270d2ce33b1475f500f3b9a773eb966f3f8ab5ceb738d52262bbe10cb2'
}

const bob = {
  'address': '0xdcd7ae3232acb938c68ee088305b83f6',
  'public_key': '0xe8cdd5b17a37fe7e8fe446d067e7a9907cf7783aca204ccb623972176614c0a0',
  'private_key': '0x7ea63107b0e214789fdb0d6c6e6b0d8f8b8c0be7398654ddd63f3617282be97b'
}

const tom = {
  'address': '0x14417edb1fe8c4591d739fee0a91ce42',
  'public_key': '0xc95ddc2b2926d1a451ea68fa74274aa04af97d8e2aefccb297e6ef61992d42e8',
  'private_key': '0x359059828e89fe42dddd5f9571a0c623b071379fc6287c712649dcc8c77f5eb4'
}

describe('multi-keyring', () => {

  let keyring
  beforeEach(() => {
    keyring = new MutiSignKeyring()
    // console.log(keyring)
  })

  describe('Keyring.type', () => {
    it('is a class property that returns the type string.', () => {
      const type = MutiSignKeyring.type
      assert.equal(type, TYPE_STR)
    })
  })

  describe('#type', () => {
    it('returns the correct value', () => {
      const type = keyring.type
      assert.equal(type, TYPE_STR)
    })
  })

  describe('#serialize empty wallets.', () => {
    it('serializes an empty array', async () => {
      const output = await keyring.serialize()
      assert.deepEqual(output, [])
    })
  })

  describe('#getReceiptIdentifier', () => {
    it('constructs', async () => {
      const keyring = new MutiSignKeyring([{ privateKey: testAccount.privateKey, publicKey: testAccount.publicKey }])

      keyring.getReceiptIdentifier(testAccount.address)
        .then((receiptIdentifier) => {
          console.log(receiptIdentifier)
          assert.equal(receiptIdentifier, testAccount.receiptIdentifier)
        })
    })
  })

  describe('#addAccount', () => {
    it('add alice', async () => {
      const publicKeys = [bob.public_key, tom.public_key];
      const privateKeys = [alice.private_key];

      const shardAlice = await keyring.addAccounts({ publicKeys, privateKeys, thresHold })
      console.log({ shardAlice })
      const accounts = await keyring.getAccounts()
      console.log({ accounts })
      console.log(keyring)
      assert.equal(shardAlice[0], accounts[0], 'accounts match expected')
    })
    it('add bob & tom in a same terminal', async () => {
      const publicKeys = [alice.public_key, tom.public_key];
      const privateKeys = [bob.private_key];

      const shardBob = await keyring.addAccounts({ publicKeys, privateKeys, thresHold })
      console.log({ shardBob })

      let shardTom
      try {
        const publicKeys = [alice.public_key, bob.public_key];
        const privateKeys = [tom.private_key];

        shardTom = await keyring.addAccounts({ publicKeys, privateKeys, thresHold })
        console.log({ shardTom })
      } catch (error) {
        console.log({ error })
        assert.equal(shardTom, undefined, 'shardTom should not be generated')
      }
      const accounts = await keyring.getAccounts()
      console.log({ accounts })
      assert.equal(shardBob[0], accounts[0], 'accounts match expected')
    })
  })

  describe('#export privateKey', () => {
    it('exportAccount', async () => {
      const privateKeyExpected = '0x030201547c6a1ef36e9e99865ce7ac028ee79aff404d279b568272bc7154802d4856bbc95ddc2b2926d1a451ea68fa74274aa04af97d8e2aefccb297e6ef61992d42e8e8cdd5b17a37fe7e8fe446d067e7a9907cf7783aca204ccb623972176614c0a0a9e47d270d2ce33b1475f500f3b9a773eb966f3f8ab5ceb738d52262bbe10cb2';

      const publicKeys = [bob.public_key, tom.public_key];
      const privateKeys = [alice.private_key];

      const shardAlice = await keyring.addAccounts({ publicKeys, privateKeys, thresHold })
      const accounts = await keyring.getAccounts()

      const privateKey = await keyring.exportAccount(accounts[0])
      // console.log({ privateKey })
      assert.equal(privateKey, privateKeyExpected, 'export privateKey as expected')
    })
  })

  describe('#export publicKey', () => {
    it('getPublicKeyFor', async () => {
      const publicKeyExpected = '0x547c6a1ef36e9e99865ce7ac028ee79aff404d279b568272bc7154802d4856bbc95ddc2b2926d1a451ea68fa74274aa04af97d8e2aefccb297e6ef61992d42e8e8cdd5b17a37fe7e8fe446d067e7a9907cf7783aca204ccb623972176614c0a002';
      const publicKeys = [bob.public_key, tom.public_key];
      const privateKeys = [alice.private_key];

      const shardAlice = await keyring.addAccounts({ publicKeys, privateKeys, thresHold })
      const accounts = await keyring.getAccounts()

      const publicKey = await keyring.getPublicKeyFor(accounts[0])
      // console.log({ publicKey })
      assert.equal(publicKey, publicKeyExpected, 'export publicKey as expected')
    })
  })

  describe('#export receiptIdentifier', () => {
    it('getReceiptIdentifier', async () => {
      const receiptIdentifierExpected = 'stc1pk42a3vr0a45hdxppuxym295gwq38kuqj';
      const publicKeys = [bob.public_key, tom.public_key];
      const privateKeys = [alice.private_key];

      const shardAlice = await keyring.addAccounts({ publicKeys, privateKeys, thresHold })
      const accounts = await keyring.getAccounts()

      const receiptIdentifier = await keyring.getReceiptIdentifier(accounts[0])
      // console.log({ receiptIdentifier })
      assert.equal(receiptIdentifier, receiptIdentifierExpected, 'export receiptIdentifier as expected')
    })
  })
})

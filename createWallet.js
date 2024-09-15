// Importando as dependências
const bip32 = await import('bip32');
const bip39 = await import('bip39');
const bitcoin = await import('bitcoinjs-lib');
const crypto = await import('crypto');

// Função para criptografar dados
const encrypt = (data, password) => {
  const key = crypto.createHash('sha256').update(password).digest('base64').substr(0, 32);
  const iv = crypto.randomBytes(16); 
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted; 
};

// Função para descriptografar dados
const decrypt = (data, password) => {
  const key = crypto.createHash('sha256').update(password).digest('base64').substr(0, 32);
  const parts = data.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const encryptedText = parts[1];
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};

// Definir a rede
const networks = {
  mainnet: bitcoin.networks.bitcoin,
  testnet: bitcoin.networks.testnet
};

// Escolher a rede
const userNetworkChoice = 'testnet'; 
const network = networks[userNetworkChoice];

// Derivação de carteiras HD
const path = `m/49'/1'/0'/0`;

// Criando palavras de senha (mnemonic)
let mnemonic = bip39.generateMnemonic();

// Validar o mnemonic
if (!bip39.validateMnemonic(mnemonic)) {
  throw new Error('Mnemonic inválido! Gerando novamente...');
}

const seed = bip39.mnemonicToSeedSync(mnemonic);

// Criando a raiz
let root = bip32.fromSeed(seed, network);

// Criando uma conta pvt-pub keys
let account = root.derivePath(path);
let node = account.derive(0).derive(0);

// Gerar um endereço Bitcoin
let btcAddress = bitcoin.payments.p2pkh({
  pubkey: node.publicKey,
  network: network,
}).address;

// Multisig Address
const pubkeys = [node.publicKey, root.derivePath("m/49'/1'/0'/0/1").publicKey]; // Exemplo com 2 chaves públicas
const { address: multisigAddress } = bitcoin.payments.p2sh({
  redeem: bitcoin.payments.p2ms({ m: 2, pubkeys, network })
});

// Definindo uma senha para criptografia
const password = 'senhaSegura123';

// Criptografar seed e chave privada
const encryptedSeed = encrypt(seed.toString('hex'), password);
const encryptedPrivateKey = encrypt(node.toWIF(), password);

console.log("Carteira gerada");
console.log("Endereço: ", btcAddress);
console.log("Endereço Multisig: ", multisigAddress);
console.log("Chave privada criptografada: ", encryptedPrivateKey);
console.log("Seed criptografada: ", encryptedSeed);
console.log("Mnemonic: ", mnemonic);

// Descriptografar a chave privada e seed
const decryptedPrivateKey = decrypt(encryptedPrivateKey, password);
const decryptedSeed = decrypt(encryptedSeed, password);
console.log("Chave privada descriptografada: ", decryptedPrivateKey);
console.log("Seed descriptografada: ", decryptedSeed);
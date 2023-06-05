# Multi signatures sur la blockchain

## Introduction

Les multi signatures ou "signatures multiples", sont une composante importante dans la sécurité et la décentralisation des smart contracts. En effet celles-ci permettent à plusieurs parties prédéfinies d'approuver une action à efféctuer.

Dans cette articles nous examinerons un smart contrat nommé "MultiSIgWallet" qui utilise les multi signatures. Nous étudierons sa structure, ses variables, ses modificateurs, ainsi que le processus de vérification des signatures et de transfert de fonds sécurisé.

En comprenant l'importance des multi signatures dans les contrats intelligents et en explorant le fonctionnement du smart contract, vous serez en mesure d'apprécier les avantages de cette fonctionnalité en matière de sécurité et de confiance.

## I. Utilisation des multi signatures

#### A. Définition des multi signatures

Les multi signatures, également connues sous le nom de "multisig", sont un mécanisme de sécurité utilisé dans les systèmes basés sur la blockchain pour autoriser les transactions. Une multi signature implique la nécessité d'obtenir l'approbation de plusieurs parties avant qu'une transaction puisse être validée et exécutée. Concrètement, cela signifie que plusieurs clés privées doivent être utilisées pour signer numériquement une transaction, et seules les transactions signées par un nombre suffisant de parties autorisées seront considérées comme valides.

#### B. Pourquoi utiliser les multi signatures

Les multi signatures offrent plusieurs avantages et sont largement utilisées dans le domaine des contrats intelligents et des transactions sur la blockchain. Voici quelques raisons clés pour lesquelles les multi signatures sont utilisées :

1. Sécurité renforcée : Les multi signatures permettent de renforcer la sécurité des transactions en exigeant l'approbation de plusieurs parties. Cela réduit considérablement les risques de fraude, de piratage ou d'erreurs humaines, car une seule clé privée compromise ne peut pas compromettre l'intégrité de la transaction.
2. Gestion des fonds partagés : Les multi signatures sont particulièrement utiles dans les cas où des fonds sont détenus conjointement par plusieurs parties, comme dans le cas d'une entreprise, d'une organisation ou d'un fonds commun. Les multi signatures permettent de mettre en place des processus d'approbation clairs et transparents pour les transactions impliquant ces fonds partagés.
3. Protection des utilisateurs : Les multi signatures offrent une protection supplémentaire aux utilisateurs en leur donnant un plus grand contrôle sur leurs actifs numériques. Par exemple, dans les portefeuilles de crypto-monnaies, les multi signatures peuvent être utilisées pour exiger l'approbation de plusieurs dispositifs ou adresses avant d'autoriser une transaction sortante, ce qui réduit les risques de vol ou de perte de fonds.

#### C. Les types de multi signatures

Vous pourrez trouver 2 sortes de multi signature sur la blockchain.

La première consiste pour chaque utilisateur à effectuer une transaction vers le smart contract afin de modifier une variable mapper à son adresse afin de marquer son approbation envers l'action à réaliser. Cette méthode est très efficasse puisque'elle ne nécessite pas d'intermédiaire ou de système de sécurité poussé, et l'on peut retirer sa signature à tout moment si le smart contract le permet. Toutefois elle a un défaut non négligeable, elle coute du gas (frais de transaction). En effet, chaque signature nécessite une transaction distincte. C'est pourquoi nous utiliserons ici l'autre méthode

La seconde méthode consiste cette fois à signer numériquement un message grâce à sa clé privée puis à transmettre l'intégralité des messages des utilisateurs au smart contract en une seule transaction, ce qui économise beaucoup de gas. Le smart contract vérifiera chaque signature afin de valider l'action à efféctuer. Cependant il faut noter qu'une fois la signature émise il est impossible de s'assurer son retrait. Il faut aussi ajouter différentes protections pour éviter des fraudes telles que la réutilisation de la signature ou son détournement.

## II. Fonctionnement du smart contract

#### A. Structure du contrat MultiSigWallet

Le contrat MultiSigWallet est conçu pour gérer les transactions sécurisées en utilisant des multi signatures. Il utilise la bibliothèque OpenZeppelin pour garantir la sécurité des opérations. Au cœur de ce contrat se trouve une structure appelée "WithdrawalInfo", qui stocke les informations relatives aux retraits, tels que le montant à transférer et l'adresse de destination.

```
struct WithdrawalInfo {
    uint amount;
    address to;
}
```

#### B. Variables et événements utilisés dans le contrat

Le contrat MultiSigWallet utilise plusieurs variables pour suivre l'état du contrat, notamment la variable "\_ownersCount" qui représente le nombre total de propriétaires du contrat, la variable "threshold" qui définit le nombre minimum de signatures requises pour valider une transaction, et la variable "nonce" qui assure l'utilisation unique des numéros de transaction.

```
uint256 private _ownersCount;
uint256 public threshold;
uint256 public nonce;
```

Nous utiliserons un mapping d'address "owners" afin de sauvegarder les adresses propriétaire.

```
mapping(address => bool) private owners;
```

Enfin nous utiliserons la convention d'utiliser le préfixe "\\x19Ethereum Signed Message:\\n32" devant les signatures

```
string constant private MSG_PREFIX = "\x19Ethereum Signed Message:\n32";
```

Des événements sont également déclarés, tels que "Deposit" pour signaler les dépôts effectués sur le contrat et "Withdraw" pour indiquer les transferts de fonds.

```
event Deposit(address from, uint amount);
event Withdraw(address to, uint amount);
```

#### C. Modificateurs et constructeur du contrat

Le contrat MultiSigWallet utilise le modificateur "isOwner" pour restreindre certaines fonctions aux seuls propriétaires autorisés. Ce modificateur vérifie si l'adresse émettrice de la transaction est un propriétaire enregistré dans le contrat.

```
modifier isOwner() {
    require(owners[msg.sender], "Not owner");
    _;
}
```

Le constructeur du contrat est exécuté lors du déploiement et permet d'initialiser les propriétaires et le seuil requis. Il vérifie que les adresses des propriétaires sont valides et uniques, et définit les valeurs initiales des variables correspondantes.

```
constructor(address[] memory _signers, uint256 _threshold) {
    require(_signers.length > 0, "Owners required");
    require(_threshold > 0 && _threshold <= _signers.length, "Invalid threshold");
    for (uint8 i = 0; i < _signers.length; i++) {
        require(_signers[i] != address(0), "Invalid owner");
        require(owners[_signers[i]] == false, "Owner not unique");
        owners[_signers[i]] = true;
    }
    _ownersCount = _signers.length;
    threshold = _threshold;
}
```

## III. Processus de vérification des signatures

#### A. Fonction \_processWithdrawalInfo

La fonction \_processWithdrawalInfo prend en paramètre les informations de retrait (\_txn), le nonce (\_nonce) et l'adresse du contrat (\_contractAddress). Cette fonction encode les informations de retrait, les concatène avec le nonce et l'adresse du contrat, puis calcule le hash (digest) de ces données à l'aide de la fonction de hachage keccak256. Ce hash est ensuite utilisé pour la vérification des signatures.

```
function _processWithdrawalInfo(WithdrawalInfo calldata _txn, uint256 _nonce, address _contractAddress) private pure returns(bytes32 _digest) {
    bytes memory encoded = abi.encode(_txn);
    _digest = keccak256(abi.encodePacked(encoded, _nonce, _contractAddress));
    _digest = keccak256(abi.encodePacked(MSG_PREFIX, _digest));
    return _digest;
}
```

#### B. Fonction \_verifyMultiSignature

La fonction \_verifyMultiSignature est responsable de la vérification des signatures lors d'une demande de retrait de fonds. Elle prend en paramètre les informations de retrait (\_txn), le nonce (\_nonce) et un tableau de signatures (\_multiSignature). Cette fonction effectue plusieurs vérifications cruciales : 

1. Vérification de l'utilisation unique du nonce : Le nonce doit être supérieur au dernier nonce utilisé pour éviter la réutilisation des signatures pour d'une transaction précédente.

   ```
   require(_nonce > nonce, "Nonce already used")
   ```
2. Vérification du nombre de signatures : Le nombre de signatures (\_multiSignature.length) doit être inférieur ou égal au nombre total de propriétaires (\_ownersCount) et supérieur ou égal au seuil requis (threshold). Cela garantit que le nombre approprié de propriétaires a approuvé la transaction.

   ```
   uint256 count = _multiSignature.length;
   require(count <= _ownersCount, "Invalid number of signatures");
   require(count >= threshold, "Not enough signatures");
   ```
3. Création du digest et vérification de l'adresse du contract (address(this)) : L'adresse utilisée pour créer la signature doit correspondre à l'adresse du contrat afin d'éviter l'utilisation de signatures créées pour d'autres contrats.

   ```
   bytes32 _digest = _processWithdrawalInfo(_txn, _nonce, address(this));
   ```
4. Vérification de chaque signature : La fonction récupère chaque signature du tableau \_multiSignature et utilise la fonction ECDSA.recover pour récupérer l'adresse du signataire à partir de la signature et du digest (\_processWithdrawalInfo). La signature est vérifiée pour s'assurer que le signataire est un propriétaire autorisé. Ensuite on vérifie que chaque adresse est supérieure à la précédente, cela pemet de facilement vérifier qu'il n'y ai pas de doublon dans les signatures. Toutefois cela oblige les utilisateurs à envoyer les signatures par ordre croissant des adresses de leurs signataires.

   ```
   address initSignerAddress;
   for (uint256 i = 0; i < count; i++) {
       bytes memory signature = _multiSignature[i];
       address signerAddress = ECDSA.recover(_digest, signature);
       require(signerAddress > initSignerAddress, "Invalid signature order or duplicate signature");
       require(owners[signerAddress], "Invalid signer");
       initSignerAddress = signerAddress;
   }
   ```
5. Actualisation du \_nonce : Mise à jour du nonce avec le nouveau nonce utilisé dans les signatures

   ```
   nonce = _nonce;
   ```

Fonction complète:

```
function _verifyMultiSignature(WithdrawalInfo calldata _txn, uint256 _nonce, bytes[] calldata _multiSignature) private {
    require(_nonce > nonce, "Nonce already used");
    uint256 count = _multiSignature.length;
    require(count <= _ownersCount, "Invalid number of signatures");
    require(count >= threshold, "Not enough signatures");
    bytes32 _digest = _processWithdrawalInfo(_txn, _nonce, address(this));

    address initSignerAddress;
    for (uint256 i = 0; i < count; i++) {
        bytes memory signature = _multiSignature[i];
        address signerAddress = ECDSA.recover(_digest, signature);
        require(signerAddress > initSignerAddress, "Invalid signature order or duplicate signature");
        require(owners[signerAddress], "Invalid signer");
        initSignerAddress = signerAddress;
    }
    nonce = _nonce;
}
```

#### C. Processus de vérification des signatures et condition de seuil

Pour qu'une transaction soit valide, le nonce doit être plus élevé que le dernier utilisé, le nombre de signatures doit être suffisant, l'adresse utilisé dans la signature doit correspondre au contrat et chaque signature doit provenir d'un propriétaire autorisé unique.

La condition de seuil (threshold) détermine le nombre minimum de signatures requises pour valider une transaction. Si le nombre de signatures valides est inférieur au seuil, la transaction est rejetée.

## IV. Transfert de fonds sécurisé

#### A. Fonction \_transferETH

La fonction \_transferETH est chargée d'effectuer le transfert sécurisé des fonds vers une adresse spécifiée après la vérification des signatures. Elle prend en paramètre les informations de retrait (\_txn) contenant le montant (\_txn.amount) et l'adresse de destination (\_txn.to). Cette fonction utilise la fonction call{value: \_txn.amount}("") pour transférer le montant spécifié à l'adresse de destination. En cas d'échec du transfert, une exception est levée.

```
function _transferETH(WithdrawalInfo calldata _txn) private {
    (bool success, ) = payable(_txn.to).call{value: _txn.amount}("");
    require(success, "Transfer failed");
}
```

#### B. Fonction withdrawETH

La fonction withdrawETH est l'interface publique permettant d'initier un retrait de fonds sécurisé. Elle prend en paramètre les informations de retrait (\_txn), le nonce (\_nonce) et un tableau de signatures (\_multiSignature). Avant d'effectuer le transfert, cette fonction vérifie la validité des signatures à l'aide de la fonction \_verifyMultiSignature. Si les signatures sont valides, la fonction appelle la fonction interne \_transferETH pour effectuer le transfert sécurisé des fonds. Enfin, elle émet un événement "Withdraw" pour notifier la réussite du transfert.

```
function withdrawETH(WithdrawalInfo calldata _txn, uint256 _nonce, bytes[] calldata _multiSignature) external nonReentrant isOwner {
    require(_txn.amount > 0, "Invalid amount");
    require(address(this).balance >= _txn.amount, "Insufficient balance");
    _verifyMultiSignature(_txn, _nonce, _multiSignature);
    _transferETH(_txn);
    emit Withdraw(_txn.to, _txn.amount);
}
```

#### C. Illustration du transfert de fonds sécurisé à l'aide de signatures multiples

Le processus de transfert de fonds sécurisé avec le contrat MultiSigWallet nécessite plusieurs étapes. Tout d'abord, les propriétaires autorisés doivent signer numériquement la transaction à l'aide de leurs clés privées respectives. Ces signatures sont ensuite fournies à la fonction withdrawETH, avec les informations de retrait et le nonce.

Lors de l'appel de la fonction withdrawETH, les signatures sont vérifiées à l'aide de la fonction \_verifyMultiSignature. Si le seuil requis est atteint et que toutes les signatures sont valides, le transfert de fonds est autorisé. La fonction \_transferETH est ensuite appelée pour effectuer le transfert sécurisé des fonds vers l'adresse de destination spécifiée dans les informations de retrait.

Grâce à ce processus, les transferts de fonds effectués via le contrat MultiSigWallet bénéficient d'une sécurité renforcée grâce aux signatures multiples, ce qui permet une décentralisation du pouvoir de transfert de fonds.

## V. Conclusion

Les multi signatures sur la blockchain offrent une couche supplémentaire de sécurité et de confiance dans les contrats intelligents. Elles permettent des transactions fiables et résistante à la fraude. Les avantages des multi signatures incluent la réduction des risques de manipulation, la prévention des transactions non autorisées et la protection des actifs des utilisateurs.

Il est important de souligner que l'utilisation des multi signatures nécessite des pratiques de sécurité appropriées, telles que la gestion sécurisée des clés privées et la sécurisation du partage et de la récupération des signatures. La sécurité et les bonnes pratiques sont des éléments clés pour garantir le bon fonctionnement des contrats utilisant les multi signatures.

Avec une utilisation judicieuse des multi signatures, nous pouvons continuer à exploiter les avantages de la blockchain dans divers domaines, tels que les finances décentralisées, les systèmes de vote, la gestion des actifs numériques, et bien d'autres encore. La sécurité et la confiance sont au cœur de cette technologie, et les multi signatures jouent un rôle crucial pour renforcer ces aspects fondamentaux.

## VI. Références

- Smart contract MultiSigWallet : <https://github.com/ereynier/MultiSigWallet/blob/718a6ab5619fa617425a157bffa1e2dd470c3d59/MultiSigWallet.sol>
- Bibliothèque OpenZeppelin : <https://github.com/OpenZeppelin/openzeppelin-contracts>
- Inspiration pour la création du smart contract: <https://www.codementor.io/@beber89/build-a-basic-multisig-vault-in-solidity-for-ethereum-1tisbmy6ze>
- Unchecked CALL Return Values: <https://blog.sigmaprime.io/solidity-security.html#unchecked-calls>
- Replay Attack : <https://blog.finxter.com/smart-contract-replay-attack-solidity/>
- Reentrancy attack : <https://github.com/kadenzipfel/smart-contract-vulnerabilities/blob/master/vulnerabilities/reentrancy.md>

*Estéban Reynier* 

site: <http://ereynier.me>

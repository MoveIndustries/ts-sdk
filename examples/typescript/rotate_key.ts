/* eslint-disable no-console */

import {
  Account,
  AccountAddress,
  Ed25519Account,
  MovementConfig,
  Network,
  NetworkToNetworkName
} from "@moveindustries/ts-sdk";

const WIDTH = 16;

// Set up the client
const MOVEMENT_NETWORK: Network = NetworkToNetworkName[process.env.MOVEMENT_NETWORK ?? Network.DEVNET];
const config = new MovementConfig({ network: MOVEMENT_NETWORK });
const movement = new Movement(config);

function truncate(address: AccountAddress): string {
  return `${address.toString().substring(0, 6)}...${address
    .toString()
    .substring(address.toString().length - 4, address.toString().length)}`;
}

function formatAccountInfo(account: Ed25519Account): string {
  const vals: any[] = [account.accountAddress, account.publicKey.authKey(), account.privateKey, account.publicKey];
  return vals.map((v) => truncate(v).padEnd(WIDTH)).join(" ");
}

(async () => {
  const alice = Account.generate();
  const bob = Account.generate();

  await movement.fundAccount({ accountAddress: alice.accountAddress, amount: 1000000000 });
  await movement.fundAccount({ accountAddress: bob.accountAddress, amount: 1000000000 });

  console.log(
    `\n${"Account".padEnd(WIDTH)} ${"Address".padEnd(WIDTH)} ${"Auth Key".padEnd(WIDTH)} ${"Private Key".padEnd(
      WIDTH,
    )} ${"Public Key".padEnd(WIDTH)}`,
  );
  console.log("---------------------------------------------------------------------------------");
  console.log(`${"alice".padEnd(WIDTH)} ${formatAccountInfo(alice)}`);
  console.log(`${"bob".padEnd(WIDTH)} ${formatAccountInfo(bob)}`);
  console.log("\n...rotating...".padStart(WIDTH));

  // Rotate the key!
  await movement.rotateAuthKey({ fromAccount: alice, toNewPrivateKey: bob.privateKey });

  const aliceNew = Account.fromPrivateKey({ privateKey: bob.privateKey, address: alice.accountAddress });

  console.log(`\n${"alice".padEnd(WIDTH)} ${formatAccountInfo(aliceNew)}`);
  console.log(`${"bob".padEnd(WIDTH)} ${formatAccountInfo(bob)}\n`);
})();

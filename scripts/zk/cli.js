#!/usr/bin/env node
/*
 * JSON-over-stdin bridge so the Python node can use the ZK library.
 *
 *   echo '{"cmd":"identity"}' | node scripts/zk/cli.js
 *   echo '{"cmd":"commitment","secret":"123"}' | node scripts/zk/cli.js
 *   echo '{"cmd":"prove","secret":"..","members":[..],"scope":"..","signalHash":".."}' | node scripts/zk/cli.js
 *
 * Writes one JSON object to stdout. BigInts are returned as decimal strings.
 */
const zk = require("./lib");

function readStdin() {
  return new Promise((resolve) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (c) => (data += c));
    process.stdin.on("end", () => resolve(data));
  });
}

const str = (o) => JSON.stringify(o, (_, v) => (typeof v === "bigint" ? v.toString() : v));

(async () => {
  try {
    const req = JSON.parse(await readStdin());
    let out;
    if (req.cmd === "identity") {
      out = await zk.newIdentity();
    } else if (req.cmd === "commitment") {
      out = { commitment: await zk.commitmentOf(req.secret) };
    } else if (req.cmd === "prove") {
      const r = await zk.prove(req);
      out = { proof: r.proof, nullifier: r.nullifier, root: r.root, publicSignals: r.publicSignals };
    } else {
      throw new Error(`unknown cmd ${req.cmd}`);
    }
    process.stdout.write(str(out));
    process.exit(0);
  } catch (e) {
    process.stdout.write(str({ error: e.message }));
    process.exit(1);
  }
})();

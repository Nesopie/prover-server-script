import { ec as EC } from "elliptic";
import axios from "axios";
import * as crypto from "crypto";
import rsaInputs from "./inputs/rsa.json";
import rsaPublicInputs from "./public_inputs/rsa.json";
import ecdsaInputs from "./inputs/ecdsa.json";
import ecdsaPublicInputs from "./public_inputs/ecdsa.json";

function encryptAES256GCM(plaintext, key) {
  const iv = crypto.randomBytes(12); // GCM standard uses a 12-byte IV

  console.log(key.length);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  let encrypted = cipher.update(plaintext, "utf8", "hex");
  encrypted += cipher.final("hex");

  const authTag = cipher.getAuthTag();

  return {
    nonce: Array.from(Buffer.from(iv.toString("hex"), "hex")),
    cipher_text: Array.from(Buffer.from(encrypted, "hex")),
    auth_tag: Array.from(Buffer.from(authTag.toString("hex"), "hex")),
  };
}

const ec = new EC("p256");

const key1 = ec.genKeyPair();

const pubkey =
  key1.getPublic().getX().toString("hex").padStart(64, "0") +
  key1.getPublic().getY().toString("hex").padStart(64, "0");
const helloBody = {
  jsonrpc: "2.0",
  method: "openpassport_hello",
  id: 1,
  params: {
    user_pubkey: [4, ...Array.from(Buffer.from(pubkey, "hex"))],
  },
};

const circuitNames = [
  "proveSha1Sha1Sha1Rsa655374096",
  "proveSha256Sha256Sha256EcdsaBrainpoolP256r1",
];

const inputs = [rsaInputs, ecdsaInputs];
const publicInputs = [rsaPublicInputs, ecdsaPublicInputs];

(async () => {
  for (let i = 0; i < 10; i++) {
    const helloRes = await axios.post("http://localhost:3001", helloBody);
    const serverPubkey = await helloRes.data.result.pubkey;

    const key2 = ec.keyFromPublic(serverPubkey, "hex");

    const index = i % 2;

    const sharedKey = key1.derive(key2.getPublic());

    const encryptionData = encryptAES256GCM(
      JSON.stringify({
        type: "register",
        prove: {
          name: circuitNames[index],
          inputs: JSON.stringify(inputs[index]),
          public_inputs: JSON.stringify(publicInputs[index]),
        },
      }),
      Buffer.from(sharedKey.toString("hex").padStart(64, "0"), "hex")
    );

    const submitBody = {
      jsonrpc: "2.0",
      method: "openpassport_submit_request",
      id: 1,
      params: {
        uuid: helloRes.data.result.uuid,
        ...encryptionData,
      },
    };

    const submitRes = await axios.post("http://localhost:3001", submitBody);
    console.log(submitRes.data);
  }
})();

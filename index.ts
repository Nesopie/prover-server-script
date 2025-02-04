import elliptic from "elliptic";
import axios from "axios";
import * as crypto from "crypto";
import rsaInputs from "./inputs/rsa.json";
import rsaPublicInputs from "./public_inputs/rsa.json";
import ecdsaInputs from "./inputs/ecdsa.json";
import ecdsaPublicInputs from "./public_inputs/ecdsa.json";
import WebSocket from "ws";
import { verifyAttestion } from "./attest";

const { ec: EC } = elliptic;
const rpcUrl = "ws://65.2.56.192:8888/";
const wsUrl = "ws://65.2.56.192:8890/";
// ("ws://ad3c378249c1242619c12616bbbc4036-28818039163c2199.elb.eu-west-1.amazonaws.com:8890/");

function encryptAES256GCM(plaintext, key) {
  const iv = crypto.randomBytes(12); // GCM standard uses a 12-byte IV

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
  "registerSha1Sha256Sha256Rsa655374096",
  "registerSha256Sha256Sha256EcdsaBrainpoolP256r1",
];

const inputs = [rsaInputs, ecdsaInputs];
const publicInputs = [rsaPublicInputs, ecdsaPublicInputs];

(async () => {
  for (let i = 0; i < 2; i++) {
    const ws = new WebSocket(rpcUrl);

    ws.on("open", async () => {
      ws.send(JSON.stringify(helloBody));
    });

    ws.on("message", async (data) => {
      let textDecoder = new TextDecoder();
      let result = JSON.parse(textDecoder.decode(Buffer.from(data)));
      console.log(result);
      if (result.result.attestation !== undefined) {
        const { userData, pubkey } = await verifyAttestion(
          result.result.attestation
        );
        //check if key1 is the same as userData
        const serverPubkey = pubkey!;
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
            uuid: result.result.uuid,
            ...encryptionData,
          },
        };
        ws.send(JSON.stringify(submitBody));
      } else {
        const uuid = result.result;
        const ws2 = new WebSocket(wsUrl);
        ws2.addEventListener("open", () => {
          console.log("opened websocket server");
          ws2.send(uuid);
        });
        ws2.addEventListener("error", (err) => {
          console.error("WebSocket error:", err);
        });
        ws2.addEventListener("message", (event) => {
          // console.log(JSON.parse(event.data.toString()));
          const message = JSON.parse(event.data.toString());
          console.log(message);
          if (message.proof !== null) {
            ws2.close();
            ws.close();
          }
        });
        ws2.addEventListener("close", (event) => {
          console.log(
            `WebSocket closed. Code: ${event.code}, Reason: ${event.reason}`
          );
        });
      }
    });
  }
})();

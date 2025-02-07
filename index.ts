import elliptic from "elliptic";
import axios from "axios";
import * as crypto from "crypto";
import rsaInputs from "./inputs/rsa.json";
import rsaPublicInputs from "./public_inputs/rsa.json";
import ecdsaInputs from "./inputs/ecdsa.json";
import ecdsaPublicInputs from "./public_inputs/ecdsa.json";
import WebSocket from "ws";
import { verifyAttestion } from "./attest";
import { v4 } from "uuid";

const { ec: EC } = elliptic;
const rpcUrl = "ws://3.110.229.45:8888/";
// const wsUrl = "ws://43.205.137.10:8888/";
const wsUrl = "ws://localhost:3002/";

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

const circuitNames = [
  "register_sha1_sha256_sha256_rsa_65537_4096",
  "register_sha256_sha256_sha256_ecdsa_brainpoolP256r1",
];

const inputs = [rsaInputs, ecdsaInputs];
const publicInputs = [rsaPublicInputs, ecdsaPublicInputs];

(async () => {
  for (let i = 0; i < 2; i++) {
    const pubkey =
      key1.getPublic().getX().toString("hex").padStart(64, "0") +
      key1.getPublic().getY().toString("hex").padStart(64, "0");
    const helloBody = {
      jsonrpc: "2.0",
      method: "openpassport_hello",
      id: 1,
      params: {
        user_pubkey: [4, ...Array.from(Buffer.from(pubkey, "hex"))],
        uuid: v4(),
      },
    };
    const ws = new WebSocket(rpcUrl);

    ws.on("open", async () => {
      ws.send(JSON.stringify(helloBody));
    });

    ws.on("close", () => {
      console.log("WebSocket closed");
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
            circuit: {
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
            onchain: true,
          },
        };
        ws.send(JSON.stringify(submitBody));
      } else {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        const uuid = result.result;
        const ws2 = new WebSocket(wsUrl);

        let interval;

        ws2.addEventListener("open", () => {
          console.log("opened websocket server");
          ws2.send(`subscribe_${uuid}`);
          // interval = setInterval(() => {
          //   ws2.send(`request_${uuid}`);
          // }, 2000);
        });
        ws2.addEventListener("error", (err) => {
          console.error("WebSocket error:", err);
        });
        ws2.addEventListener("message", (event) => {
          const message = JSON.parse(event.data.toString());
          console.log(message);
          if (message.proof !== null) {
            clearInterval(interval);
            console.log("hi");
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

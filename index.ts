import elliptic from "elliptic";
import axios from "axios";
import * as crypto from "crypto";
import rsaInputs from "./inputs/rsa.json";
import ecdsaInputs from "./inputs/ecdsa.json";
import dscRsaInputs from "./inputs/dsc_rsa.json";
import discloseInputs from "./inputs/disclose.json";
import WebSocket from "ws";
import { verifyAttestion } from "./attest";
import { v4 } from "uuid";
import { io } from "socket.io-client";

const { ec: EC } = elliptic;

const wsUrl = "";
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
  "dsc_sha256_rsa_65537_4096",
  "vc_and_disclose",
];

const inputs = [rsaInputs, ecdsaInputs, dscRsaInputs, discloseInputs];

const rpcUrls = [];

const circuitTypes = ["register", "register", "dsc", "disclose"];
(async () => {
  for (let i = 0; i < 1; i++) {
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
    const ws = new WebSocket(rpcUrls[i]);

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
        const sharedKey = key1.derive(key2.getPublic());

        const endpoint =
          circuitTypes[i] === "disclose"
            ? { endpointType: "celo", endpoint: "http://random_url.com" }
            : {};

        const encryptionData = encryptAES256GCM(
          JSON.stringify({
            type: circuitTypes[i],
            onchain: true,
            ...endpoint,
            circuit: {
              name: circuitNames[i],
              inputs: JSON.stringify(inputs[i]),
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
        await new Promise((resolve) => setTimeout(resolve, 3000));
        const uuid = result.result;
        const socket2 = io(wsUrl, { transports: ["websocket"] });
        socket2.on("connect", () => {
          console.log("Connected to Socket.IO server");
          socket2.emit("subscribe", uuid);
        });
        socket2.on("error", (err) => {
          console.error("Socket.IO error:", err);
        });
        socket2.on("status", (data) => {
          try {
            console.log(data);
            if (data.proof !== null) {
              console.log("Proof received. Closing connections.");
              socket2.disconnect();
              ws.close();
            }
          } catch (e) {
            console.error("Error parsing message:", e);
          }
        });
        socket2.on("disconnect", (reason) => {
          console.log(`Socket.IO disconnected: ${reason}`);
        });
      }
    });
  }
})();

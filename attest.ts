import cbor from "cbor";
import { aws_root_cert_pem } from "./aws_root_pem";
import { Certificate } from "@fidm/x509";
import cose from "cose-js";
import asn1 from "asn1.js";

const requiredFields = [
  "module_id",
  "digest",
  "timestamp",
  "pcrs",
  "certificate",
  "cabundle",
];

const ECPublicKeyASN = asn1.define("ECPublicKey", function () {
  this.seq().obj(
    this.key("algo")
      .seq()
      .obj(this.key("id").objid(), this.key("curve").objid()),
    this.key("pubKey").bitstr()
  );
});

const numberInRange = (start: number, end: number, value: number) => {
  return value > start && value <= end;
};

function derToPem(der: Buffer): string {
  const base64 =
    der
      .toString("base64")
      .match(/.{1,64}/g)
      ?.join("\n") ?? "";
  return `-----BEGIN CERTIFICATE-----\n${base64}\n-----END CERTIFICATE-----`;
}

const verifyCertChain = (rootPem: string, certChainStr: string[]): boolean => {
  const rootCert = Certificate.fromPEM(Buffer.from(rootPem));
  const certChainPartial = certChainStr.map((c) =>
    Certificate.fromPEM(Buffer.from(c))
  );
  const certChain = [rootCert, ...certChainPartial];

  for (let i = 1; i < certChain.length - 1; i++) {
    const isValid = certChain[i - 1].publicKey.verify(
      certChain[i].tbsCertificate.toDER(),
      certChain[i].signature,
      "sha384"
    );
    if (!isValid) {
      console.error(
        `Certificate at index ${i} is not properly signed by the next certificate.`
      );
      return false;
    }
  }
  return true;
};

function rmPadding(buf: Array<number>): Array<number> {
  var i = 0;
  var len = buf.length - 1;
  while (!buf[i] && !(buf[i + 1] & 0x80) && i < len) {
    i++;
  }
  if (i === 0) {
    return buf;
  }
  return buf.slice(i);
}

function constructLength(arr: Array<number>, len: number) {
  if (len < 0x80) {
    arr.push(len);
    return;
  }
  var octets = 1 + ((Math.log(len) / Math.LN2) >>> 3);
  arr.push(octets | 0x80);
  while (--octets) {
    arr.push((len >>> (octets << 3)) & 0xff);
  }
  arr.push(len);
}

const toDER = function toDER(rBuf: Buffer, sBuf: Buffer): Buffer {
  var r = Array.from(rBuf);
  var s = Array.from(sBuf);

  // Pad values
  if (r[0] & 0x80) r = [0].concat(r);
  // Pad values
  if (s[0] & 0x80) s = [0].concat(s);

  r = rmPadding(r);
  s = rmPadding(s);

  while (!s[0] && !(s[1] & 0x80)) {
    s = s.slice(1);
  }
  var arr = [0x02];
  constructLength(arr, r.length);
  arr = arr.concat(r);
  arr.push(0x02);
  constructLength(arr, s.length);
  var backHalf = arr.concat(s);
  var res = [0x30];
  constructLength(res, backHalf.length);
  res = res.concat(backHalf);

  return Buffer.from(res);
};

export const verifyAttestion = async (attestation: Array<number>) => {
  // const jsonRpcBody = {
  //   jsonrpc: "2.0",
  //   method: "openpassport_attestation",
  //   id: 1,
  //   params: {},
  // };

  // const res = await axios.post(
  //   "http://ad3c378249c1242619c12616bbbc4036-28818039163c2199.elb.eu-west-1.amazonaws.com:8888/",
  //   jsonRpcBody
  // );

  const coseSign1 = await cbor.decodeFirst(Buffer.from(attestation));

  if (!Array.isArray(coseSign1) || coseSign1.length !== 4) {
    throw new Error("Invalid COSE_Sign1 format");
  }

  const [protectedHeader, unprotectedHeader, payload, signature] = coseSign1;

  const attestationDoc = (await cbor.decodeFirst(payload)) as AttestationDoc;

  for (const field of requiredFields) {
    //@ts-ignore
    if (!attestationDoc[field]) {
      throw new Error(`Missing required field: ${field}`);
    }
  }

  if (!(attestationDoc.module_id.length > 0)) {
    throw new Error("Invalid module_id");
  }
  if (!(attestationDoc.digest === "SHA384")) {
    throw new Error("Invalid digest");
  }

  if (!(attestationDoc.timestamp > 0)) {
    throw new Error("Invalid timestamp");
  }

  //for each key, value in pcts
  for (const [key, value] of attestationDoc.pcrs) {
    if (key < 0 || key >= 32) {
      throw new Error("Invalid pcr index");
    }

    if (![32, 48, 64].includes(value.length)) {
      throw new Error("Invalid pcr value length at: " + key);
    }
  }

  if (!(attestationDoc.cabundle.length > 0)) {
    throw new Error("Invalid cabundle");
  }

  for (let i = 0; i < attestationDoc.cabundle.length; i++) {
    if (!numberInRange(0, 1024, attestationDoc.cabundle[i].length)) {
      throw new Error("Invalid cabundle");
    }
  }

  if (attestationDoc.public_key) {
    if (!numberInRange(0, 1024, attestationDoc.public_key.length)) {
      throw new Error("Invalid public_key");
    }
  }

  if (attestationDoc.user_data) {
    if (!numberInRange(-1, 512, attestationDoc.user_data.length)) {
      throw new Error("Invalid user_data");
    }
  }

  if (attestationDoc.nonce) {
    if (!numberInRange(-1, 512, attestationDoc.nonce.length)) {
      throw new Error("Invalid nonce");
    }
  }

  const certChain = attestationDoc.cabundle.map((cert: Buffer) =>
    derToPem(cert)
  );

  const cert = derToPem(attestationDoc.certificate);

  if (!verifyCertChain(aws_root_cert_pem, [...certChain, cert])) {
    throw new Error("Invalid certificate chain");
  }

  const finalCert = Certificate.fromPEM(Buffer.from(cert));
  const publicKeyDer = finalCert.publicKeyRaw;
  const decoded = ECPublicKeyASN.decode(publicKeyDer, "der");
  const pubKeyBuffer = Buffer.from(decoded.pubKey.data);

  const x = pubKeyBuffer.subarray(1, 49).toString("hex");
  const y = pubKeyBuffer.subarray(49).toString("hex");

  const verifier = {
    key: {
      x,
      y,
    },
  };

  await cose.sign.verify(Buffer.from(attestation), verifier, {
    defaultType: 18,
  });

  return {
    userData: attestationDoc.user_data,
    pubkey: attestationDoc.public_key,
  };
};

type AttestationDoc = {
  module_id: string;
  digest: string;
  timestamp: number;
  pcrs: Map<number, Buffer>;
  certificate: Buffer;
  cabundle: Array<Buffer>;
  public_key: string | null;
  user_data: string | null;
  nonce: string | null;
};

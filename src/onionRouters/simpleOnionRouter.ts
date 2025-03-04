import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import { generateRsaKeyPair, exportPubKey, exportPrvKey, rsaDecrypt, symDecrypt } from "../crypto";
import { webcrypto } from "crypto";

declare global {
  var nodeKeys: Record<number, { publicKey: webcrypto.CryptoKey; privateKey: webcrypto.CryptoKey }>;
  var nodeStates: Record<number, {
    lastReceivedEncryptedMessage: string | null;
    lastReceivedDecryptedMessage: string | null;
    lastMessageDestination: number | null;
  }>;
}

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  // global storage of the keys
  if (!globalThis.nodeKeys) {
    globalThis.nodeKeys = {};
  }

  // check if key already exist
  if (!globalThis.nodeKeys[nodeId]) {
    globalThis.nodeKeys[nodeId] = await generateRsaKeyPair();
  }

  if (!globalThis.nodeStates) {
    globalThis.nodeStates = {};
  }
  if (!globalThis.nodeStates[nodeId]) {
    globalThis.nodeStates[nodeId] = {
      lastReceivedEncryptedMessage: null,
      lastReceivedDecryptedMessage: null,
      lastMessageDestination: null
    };
  }

  const { publicKey, privateKey } = globalThis.nodeKeys[nodeId];
  const publicKeyBase64 = await exportPubKey(publicKey);
  const privateKeyBase64 = await exportPrvKey(privateKey);

  const registerNode = async () => {
    try {
      const response = await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          nodeId,
          pubKey: publicKeyBase64,
        }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error: ${response.status}`);
      }

      const data = await response.json();
      console.log("Server response:", data);
    } catch (error) {
      console.error("Error during the register:", error);
    }
  };
  registerNode();

  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });

  // GET LastReceivedEncryptedMessage
  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: globalThis.nodeStates[nodeId].lastReceivedEncryptedMessage });
  });

  // GET LastReceivedDecryptedMessage
  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: globalThis.nodeStates[nodeId].lastReceivedDecryptedMessage });
  });

  // GET LastMessageDestination
  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: globalThis.nodeStates[nodeId].lastMessageDestination });
  });

  // Get Private key
  onionRouter.get("/getPrivateKey", (req, res) => {
    res.json({ result: privateKeyBase64 });
  });

  // POST message
  onionRouter.post("/message", async (req, res) => {
    try {
      const { message }: { message: string } = req.body;
      if(!message){
        res.status(400).json({error: "Missing message"});
        return ;
      }
      // Decrypt the symmetric key
      const encryptedSymKey = message.slice(0, 344);
      const restOfMessage = message.slice(344);
      const symKey = await rsaDecrypt(encryptedSymKey, privateKey);

      // Decrypt the rest of the message
      const decryptedMessage = await symDecrypt(symKey, restOfMessage);
      const nextDestination = parseInt(decryptedMessage.slice(0, 10), 10);
      const nextMessage = decryptedMessage.slice(10);
      console.log(`message: ${message}`)
      console.log(`nextDestination: ${nextDestination}`)
      console.log(`nextMessage: ${nextMessage}`)

      globalThis.nodeStates[nodeId].lastReceivedEncryptedMessage = message;
      globalThis.nodeStates[nodeId].lastReceivedDecryptedMessage = nextMessage;
      globalThis.nodeStates[nodeId].lastMessageDestination = nextDestination;

      const nextUrl = `http://localhost:${nextDestination}/message`;

      const response = await fetch(nextUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: nextMessage }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error: ${response.status}`);
      }
      res.json({ status: "Message decrypt successfully" });

    } catch (error) {
      console.error("Error while decrypting the message:", error);
      res.status(500).json({ error: "Internal error while sending the message" });
    }
  });

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
        `Onion router ${nodeId} is listening on port ${
            BASE_ONION_ROUTER_PORT + nodeId
        }`
    );
  });

  return server;
}

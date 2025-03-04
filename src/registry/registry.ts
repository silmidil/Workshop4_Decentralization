import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

const registeredNodes: Node[] = [];

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  _registry.get("/status", (req, res) => {
    res.send("live");
  });

  // POST registerNode
  _registry.post("/registerNode", (req, res) => {
    const { nodeId, pubKey }: RegisterNodeBody = req.body;

    if (nodeId === undefined || typeof nodeId !== "number" || !pubKey) {
      res.status(400).json({ error: "Missing nodeId or pubKey" });
      return;
    }

    // Prevent duplicate registration
    if (registeredNodes.some(node => node.nodeId === nodeId)) {
      res.status(400).json({ error: "Node is already registered" });
      return;
    }

    registeredNodes.push({ nodeId, pubKey });
    console.log(`Node ${nodeId} registered with public key: ${pubKey}`);

    res.json({ status: "Node registered successfully" });
  });

  // Get NodeRegistry
  _registry.get("/getNodeRegistry", (req, res) => {
    res.json({ nodes: registeredNodes });
  });

  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}

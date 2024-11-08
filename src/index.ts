import express, { Request, Response } from "express";
import dotenv from "dotenv";
import { createHmac } from "crypto";
import cors from "cors";
// Load environment variables
dotenv.config();

const app = express();

// Middleware to parse JSON
app.use(express.json());
app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    exposedHeaders: "Set-Cookie",

    allowedHeaders: ["Content-Type", "Authorization"],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    credentials: true, // Allow credentials (cookies, authorization headers, etc.)
  })
);
// Basic Route
app.get("/", (req: Request, res: Response) => {
  res.send("Hello, Express with TypeScript!");
});

app.get("/", (req: Request, res: Response) => {
  res.send("Hello, Express with TypeScript!");
});

// Function to encode data
function encodeData(data: any): Buffer {
  const formattedData = JSON.stringify(data);
  return Buffer.from(formattedData, "utf-8");
}

// Function to verify the signature
function verifySignature(
  encodedData: Buffer,
  receivedSignature: string,
  secret: string
): boolean {
  const computedSignature = createHmac("sha256", secret)
    .update(encodedData)
    .digest("hex");

  return computedSignature === receivedSignature;
}

// Function to verify timestamp is within 5 minutes
function verifyTimestamp(timestamp: number): boolean {
  const now = Math.round(Date.now() / 1000);
  const fiveMinutes = 5 * 60 * 1000;

  return now - timestamp <= fiveMinutes;
}

// Webhook route
app.post("/verification/webhook", async (req: Request, res: Response) => {
  const body = req.body;
  const signature = req.headers["x-signature"] as string;
  const secret = process.env.WEBHOOK_SECRET_KEY;

  if (!signature || !secret) {
    res.status(401).json({
      message: "Unauthorized",
    });
  }

  // Check timestamp, created_at in body, 5 min window
  const timestamp = body.created_at;
  if (!verifyTimestamp(timestamp)) {
    res.status(401).json({
      message: "Unauthorized",
    });
  }

  const encodedData = encodeData(body);

  if (verifySignature(encodedData, signature, secret as string)) {
    // Just return a 200 status with a message, no DB operation
    res.status(200).json({ message: "Webhook event processed successfully" });
  } else {
    res.status(401).json({
      message: "Unauthorized",
    });
  }
});

app.post("/proxy/session", async (req, res) => {
  try {
    console.log(req.headers.authorization, "authorization");

    console.log(req.body, "req body");

    const response = await fetch("https://verification.didit.me/v1/session/", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${req.headers.authorization}`, // Pass the token from the client
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(req.body), // Pass client request body
    });
    console.log(response, "response");

    const data = await response.json();
    res.status(response.status).json(data);
  } catch (error) {
    console.log(error, "error");
    res.status(500).json({ error: "Proxy request failed" });
  }
});

// Start server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

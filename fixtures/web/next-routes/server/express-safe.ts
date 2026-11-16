import cors from "cors";
import express from "express";

const app = express();
// NEGATIVE (WEB-CORS-006): explicit allowlist with credentials.
app.use(cors({ origin: ["https://app.example"], credentials: true }));
// NEGATIVE: reflecting without credentials (no cookies are sent cross-origin).
app.use("/public", cors({ origin: true }));

export default app;

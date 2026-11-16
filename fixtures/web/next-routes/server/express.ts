import cors from "cors";
import express from "express";

const app = express();
// POSITIVE (WEB-CORS-006, high) line 6: origin: true reflects every origin, with credentials.
app.use(cors({ origin: true, credentials: true }));

export default app;

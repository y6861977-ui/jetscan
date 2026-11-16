import { initializeApp } from "firebase/app";

// NEGATIVE: the Firebase web config is public by design; only the security rules protect data.
export const app = initializeApp({
  apiKey: "@@FIREBASE_API_KEY@@",
  authDomain: "jetscan-fixture.firebaseapp.com",
  projectId: "jetscan-fixture",
});

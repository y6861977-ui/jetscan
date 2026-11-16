"use client";

// NEGATIVE file: keys that are public by design and belong in the browser.
import { createClient } from "@supabase/supabase-js";
import { initializeApp } from "firebase/app";

export const stripePublishable = "@@STRIPE_PUBLISHABLE@@";

export const firebase = initializeApp({
  apiKey: "@@FIREBASE_API_KEY@@",
  authDomain: "jetscan-fixture.firebaseapp.com",
  projectId: "jetscan-fixture",
});

export const supabase = createClient("https://jetscanfixture.supabase.co", "@@SUPABASE_ANON_JWT@@");
export const supabaseNew = createClient("https://jetscanfixture.supabase.co", "@@SB_PUBLISHABLE@@");

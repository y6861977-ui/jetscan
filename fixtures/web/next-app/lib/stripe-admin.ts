import "server-only";

// NEGATIVE (WEB-SECRET-001): importing "server-only" makes a client import a build error.
export const stripeAdminKey = "@@STRIPE_SECRET@@";

"use strict";

// Shared by warning.js and scanning.js (loaded first as a classic script).

const SECOND_LEVEL = new Set(["co", "com", "org", "net", "gov", "ac", "edu"]);
const IP_HOST = /^(\d{1,3}(\.\d{1,3}){3}|\[.*\])$/;

// The registrable part of the hostname: what someone actually had to buy.
// A simple approximation of the public-suffix rules, good enough to show
// people which end of the address to read.
function ownerOf(host) {
  if (IP_HOST.test(host)) return host;
  const labels = host.split(".");
  const tld = labels.at(-1);
  const twoPart = labels.length >= 3 && tld.length === 2 && SECOND_LEVEL.has(labels.at(-2));
  return labels.slice(twoPart ? -3 : -2).join(".");
}

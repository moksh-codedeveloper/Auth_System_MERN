// dsa_core/hotstoreDATA.js
import { LRUCache } from "./LRUcache.js";
import { BloomFilter } from "./hashmap_user_store.js";
import prisma from "../db/db.js";

class HotDataStore {
  constructor(ttl = 10000, batchSize = 5, flushInterval = 5000) {
    this.dataMap = new Map();
    this.ttlQueue = [];
    this.bloomFilter = new BloomFilter(2048, 4);
    this.lruCache = new LRUCache(100);
    this.ttl = ttl;
    this.batchSize = batchSize;

    // Auto flush
    this.flushTimer = setInterval(() => {
      if (this.dataMap.size > 0) this.flushToDB();
    }, flushInterval);

    // Auto clean expired
    setInterval(() => this.cleanExpired(), 10000);
  }

  addUser(name, email, passwordHash) {
    if (this.bloomFilter.mightContain(email) || this.dataMap.has(email)) {
      return false;
    }
    const userData = { name, email, passwordHash, createdAt: Date.now() };
    this.dataMap.set(email, userData);
    this.bloomFilter.add(email);

    this.ttlQueue.push({ email, expiresAt: Date.now() + this.ttl });

    if (this.dataMap.size >= this.batchSize) {
      this.flushToDB();
    }
    return true;
  }

  cacheToken(token, userId) {
    this.lruCache.set(token, userId);
  }

  removeToken(token) {
    this.lruCache.cache.delete(token);
  }

  isTokenValid(token) {
    return this.lruCache.get(token) ? true : false;
  }

  cleanExpired() {
    const now = Date.now();
    this.ttlQueue = this.ttlQueue.filter(entry => {
      if (entry.expiresAt <= now) {
        this.dataMap.delete(entry.email);
        return false;
      }
      return true;
    });
  }
}

export { HotDataStore };

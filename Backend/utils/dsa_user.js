class UserDSA {
  constructor(limit = 10000) {
    this.users = new Map();
    this.sessions = new Map(); // token -> { userId, expiresAt }
    this.limit = limit;
  }

  addUser(email, user) {
    if (this.users.size >= this.limit) this.evictOldestUser();
    this.users.set(email, user);
  }

  getUser(email) {
    return this.users.get(email);
  }

  removeUser(email) {
    this.users.delete(email);
  }

  addToken(token, sessionData, ttl) {
    const expiresAt = Date.now() + ttl;
    this.sessions.set(token, { ...sessionData, expiresAt });
  }

  getToken(token) {
    const session = this.sessions.get(token);
    if (session && session.expiresAt > Date.now()) return session;
    this.sessions.delete(token);
    return null;
  }

  removeToken(token) {
    this.sessions.delete(token);
  }

  evictOldestUser() {
    const firstKey = this.users.keys().next().value;
    this.users.delete(firstKey);
  }

  cleanupSessions() {
    const now = Date.now();
    for (const [token, session] of this.sessions.entries()) {
      if (session.expiresAt <= now) this.sessions.delete(token);
    }
  }
}

export const userDsa = new UserDSA();
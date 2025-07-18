// dsa_core/hotStoreInstance.js
import { HotDataStore } from "./hotstoreDATA.js";

const hotStore = new HotDataStore(10000, 5, 5000); // TTL = 10s, batch size = 5
export { hotStore };

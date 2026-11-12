/* مخزن IndexedDB: جدول الأحداث + جدول meta */
(function (root) {
  function req(r) { return new Promise((res, rej) => { r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); }); }
  class IdbStore {
    constructor(name) { this.name = name || "agri-pharmacy"; }
    async init() {
      if (this.db) return;
      this.db = await new Promise((res, rej) => {
        const o = indexedDB.open(this.name, 1);
        o.onupgradeneeded = () => { const d = o.result; d.createObjectStore("events", { keyPath: "id" }); d.createObjectStore("meta"); };
        o.onsuccess = () => res(o.result); o.onerror = () => rej(o.error);
      });
      try { if (navigator.storage && navigator.storage.persist) navigator.storage.persist(); } catch (e) { }
    }
    async loadEvents() { await this.init(); return req(this.db.transaction("events").objectStore("events").getAll()); }
    async putEvents(list) {
      await this.init();
      return new Promise((res, rej) => { const tx = this.db.transaction("events", "readwrite"), s = tx.objectStore("events"); list.forEach(e => s.put(e)); tx.oncomplete = res; tx.onerror = () => rej(tx.error); tx.onabort = () => rej(tx.error); });
    }
    async getMeta(k) { await this.init(); const v = await req(this.db.transaction("meta").objectStore("meta").get(k)); return v === undefined ? null : v; }
    async setMeta(k, v) { await this.init(); return new Promise((res, rej) => { const tx = this.db.transaction("meta", "readwrite"); tx.objectStore("meta").put(JSON.parse(JSON.stringify(v)), k); tx.oncomplete = res; tx.onerror = () => rej(tx.error); }); }
    async clearAll() { await this.init(); return new Promise((res, rej) => { const tx = this.db.transaction(["events", "meta"], "readwrite"); tx.objectStore("events").clear(); tx.objectStore("meta").clear(); tx.oncomplete = res; tx.onerror = () => rej(tx.error); }); }
  }
  root.IdbStore = IdbStore;
})(typeof self !== "undefined" ? self : this);

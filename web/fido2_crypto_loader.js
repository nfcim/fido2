// Load before the compiled Dart application. Module URLs resolve against this page.
globalThis.fido2Crypto = {
  async initialize(url) {
    const module = await import(new URL(url, document.baseURI).href);
    await module.default();
    this.run = module.run;
    return true;
  },
  run() { throw new Error('Rust cryptography has not been initialized'); }
};

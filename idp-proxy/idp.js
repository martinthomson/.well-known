(function(g) {
  // A wrapper for the terrible indexedDB API
  function IndexedDB(name, store) {
    this.name = name;
    this.store = store;
    this._db = this._create();
  }

  IndexedDB.prototype = {
    _create: function() {
      var op = indexedDB.open(this.name);
      op.onupgradeneeded = e => {
        var db = e.target.result;
        db.createObjectStore(this.store);
      };
      return new Promise(resolve => {
        op.onsuccess = e => resolve(e.target.result);
      });
    },

    _result: function(tx, op) {
      return new Promise((resolve, reject) => {
        op.onsuccess = e => resolve(e.target.result);
        op.onerror = () => reject(op.error);
        tx.onabort = () => reject(tx.error);
      });
    },

    get: function(k) {
      return this._db.then(db => {
        var tx = db.transaction(this.store, 'readonly');
        var store = tx.objectStore(this.store);
        return this._result(tx, store.get(k));
      });
    },

    put: function(k, v) {
      return this._db.then(db => {
        var tx = db.transaction(this.store, 'readwrite');
        var store = tx.objectStore(this.store);
        return this._result(tx, store.put(v, k));
      });
    }
  };
  function DumbDB() {
    this.store_ = {}
  }
  DumbDB.prototype = {
    put: function(k, v) {
      this.store_[k] = v;
      return Promise.resolve();
    },
    get: function(k) {
      return Promise.resolve(this.store_[k]);
    }
  };

  var DB = (indexedDB) ? IndexedDB : DumbDB;

  // Base64 URL.  Again.
  var base64 = {
    _strmap: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
    encode: function(data) {
      data = new Uint8Array(data);
      var r = [];
      for (var i = 0; i < data.length;) {
        r.push(data[i] >>> 2);
        r.push(((data[i++] & 0x3) << 4) | (data[i] >>> 4));
        r.push(((data[i++] & 0xf) << 2) | (data[i] >>> 6));
        r.push(data[i++] & 0x3f);
      }
      return r.map(v => base64._strmap[v]).join('')
        .slice(0, Math.ceil(data.length * 4 / 3));
    },
    _lookup: function(s, i) {
      return base64._strmap.indexOf(s.charAt(i));
    },
    decode: function(str) {
      var v = new Uint8Array(Math.floor(str.length * 3 / 4));
      var vi = 0;
      for (var si = 0; si < str.length;) {
        var w = base64._lookup(str, si++);
        var x = base64._lookup(str, si++);
        var y = base64._lookup(str, si++);
        var z = base64._lookup(str, si++);
        v[vi++] = w << 2 | x >>> 4;
        v[vi++] = x << 4 | y >>> 2;
        v[vi++] = y << 6 | z;
      }
      return v;
    }
  };

  Promise.allmap = function(o) {
    var result = {};
    return Promise.all(
      Object.keys(o).map(
        k => Promise.resolve(o[k]).then(r => result[k] = r)
      )
    ).then(_ => result);
  }

  var idpDetails = (function() {
    var path = g.location.pathname;
    return {
      protocol: path.substring(path.lastIndexOf('/') + 1) + g.location.hash,
      domain: g.location.host
    };
  }());
  var utf8 = s => new TextEncoder('utf-8').encode(s);

  var idp = {
    generateAssertion: function(contents /*, origin, hint */) {
      var db = new DB('idpkeystore', 'keys');
      return db.get('keypair')
        .then(
          pair => pair ||
            crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' },
                                      false, ['sign'])
        )
        .then(
          pair => Promise.allmap({
            // The identity is the raw public key.
            pub:
            crypto.subtle.exportKey('raw', pair.publicKey),

            // Sign the contents
            signature:
            crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' },
                               pair.privateKey, utf8(contents))
          })
        )
        .then(result => {
          var rval = {
            idp: idpDetails,
            assertion: JSON.stringify({
              contents: contents,
              pub: base64.encode(result.pub),
              signature: base64.encode(result.signature)
            })
          };
          dump('assertion: ' + JSON.stringify(rval) + '\n');
          return rval;
        });
    },

    validateAssertion: function(assertion /*, origin */) {
      var assertion = JSON.parse(assertion); // let this throw
      return crypto.subtle.importKey('raw', base64.decode(assertion.pub),
                                     { name: 'ECDSA', namedCurve: 'P-256' },
                                     true, ['verify'])
        .then(
          pubKey => Promise.allmap({
            // Verify the signature
            ok: crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' },
                                     pubKey,
                                     base64.decode(assertion.signature),
                                     utf8(assertion.contents)),

            // Make the identity a compressed form of the public key.
            id: crypto.subtle.digest('SHA-256', utf8(assertion.pub))
              .then(raw => base64.encode(raw.slice(0, 12)))
          })
        )
        .then(result => {
          if (!result.ok) {
            throw new Error('Invalid signature on identity assertion');
          }
          var rval = {
            identity: result.id + '@' + idpDetails.domain,
            contents: assertion.contents
          };
          dump('assertion: ' + JSON.stringify(rval) + '\n');
          return rval;
        });
    }
  };

  if (g.rtcIdentityProvider) {
    g.rtcIdentityProvider.register(idp);
  } else {
    console.warn('IdP not running in the right sandbox');
    g.idp = idp;
  }
}(this));

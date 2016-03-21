function DB() {
  this.store_ = {}
}
DB.prototype = {
  put: function(k, v) {
    this.store_[k] = v;
    return Promise.resolve();
  },
  get: function(k) {
    return Promise.resolve(this.store_[k]);
  }
};

// Base64 URL.  Again.
var base64 = {
  _strmap: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
  encode: data => {
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
  _lookup: (s, i) => {
    return base64._strmap.indexOf(s.charAt(i));
  },
  decode: str => {
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

Promise.allmap = o => {
  var result = {};
  return Promise.all(
    Object.keys(o).map(
      k => Promise.resolve(o[k]).then(r => result[k] = r)
    )
  ).then(_ => result);
};

var path = location.pathname;
var idpDetails = {
  protocol: path.substring(path.lastIndexOf('/') + 1) + location.hash,
  domain: location.host
};
var utf8 = s => new TextEncoder('utf-8').encode(s);

var idp = {
  generateAssertion: (contents, origin, hint) => {
    if (!/^[-_a-zA-Z0-9]+$/.test(hint)) {
      throw new Error('Invalid name');
    }
    var rval = {
      idp: idpDetails,
      assertion: JSON.stringify({
        name: hint,
        contents: contents
      })
    };
    dump('assertion: ' + JSON.stringify(rval) + '\n');
    return Promise.resolve(rval);
  },

  validateAssertion: (assertion /*, origin */) => {
    var assertion = JSON.parse(assertion); // let this throw
    var rval = {
      identity: assertion.name + '@' + idpDetails.domain,
      contents: assertion.contents
    };
    dump('assertion: ' + JSON.stringify(rval) + '\n');
    return Promise.resolve(rval);
  }
};

if (rtcIdentityProvider) {
  rtcIdentityProvider.register({
    generateAssertion: idp.generateAssertion.bind(idp),
    validateAssertion: idp.validateAssertion.bind(idp),
  });
} else {
  console.warn('IdP not running in the right sandbox');
}

var path = location.pathname;
var idpDetails = {
  protocol: path.substring(path.lastIndexOf('/') + 1) + location.hash,
  domain: location.host
};

// This IdP is not secure at all, it is intended to show the skeleton of what
// is needed.  For a secure IdP, one of these functions needs to access
// information that only the origin has access to.  That might be accessing
// localStorage or indexedDB or it could involve making a fetch request (that
// will have cookies).
var idp = {
  generateAssertion: (contents, origin, hint) => {
    hint = hint || "anonymous";
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

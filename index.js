
var assertValid = require('assertValid');
var spawn = require('child_process').spawn;
var path = require('path');
var fs = require('fs');
var os = require('os');

var DEBUG = /^(1|true)$/.test(process.env.DEBUG);

exports.der = function certToDer(cert) {
  assertValid(cert, 'string|buffer');

  var certPath = tempPath();
  fs.writeFileSync(certPath, cert);

  var derPath = tempPath();
  return openssl([
    'x509',
    '-in', certPath,
    '-inform', 'PEM',
    '-out', derPath,
    '-outform', 'DER',
  ]).then(function() {
    var cert = fs.readFileSync(derPath);
    fs.unlinkSync(certPath);
    fs.unlinkSync(derPath);
    return cert;
  }, function(error) {
    fs.unlinkSync(certPath);
    throw error;
  });
};

exports.req = (function() {
  var optionTypes = {
    key: 'string|buffer',
    format: 'string?',
    domain: 'string?',
    domains: 'string|array?',
    subject: [{
      email: 'string?',
      country: 'string?',
      state: 'string?',
      city: 'string?',
      company: 'string?',
      division: 'string?',
    }, '?'],
  };

  var subjectKeys = {
    country: 'C',
    state: 'ST',
    city: 'L',
    company: 'O',
    division: 'OU',
  };

  exports.subjectTypes = optionTypes.subject;

  return function generateCsr(options) {
    assertValid(options, optionTypes);

    var domains = options.domains;
    if (options.domain) {
      domains = [options.domain];
    } else if (typeof domains === 'string') {
      domains = [domains];
    }
    if (!domains) {
      throw Error('Must define `options.domain` or `options.domains`');
    }

    var format = options.format || 'PEM';
    if (/^(DER|PEM)$/.test(format) == false) {
      throw Error('Unsupported CSR format: ' + format);
    }

    var csrPath = tempPath();
    var keyPath = tempPath();
    fs.writeFileSync(keyPath, options.key);

    var args = [
      'req',
      '-new',
      '-nodes',
      '-out', csrPath,
      '-key', keyPath,
    ];

    if (domains.length > 1) {
      var confPath = tempPath();
      fs.writeFileSync(confPath, createSSLConfig(confPath, domains, options.subject));
      args.push('-config', confPath);
    } else {
      args.push('-subj', subjectString(domains[0], options.subject));
    }

    if (DEBUG) {
      console.log('openssl ' + args.join(' '));
    }
    return openssl(args).then(function() {
      confPath && fs.unlinkSync(confPath);
      fs.unlinkSync(keyPath);

      // Skip converting to DER format unless specified.
      if (format === 'PEM') {
        var csr = fs.readFileSync(csrPath);
        fs.unlinkSync(csrPath);
        return csr;
      }

      var derPath = tempPath();
      var args = [
        'req',
        '-in', csrPath,
        '-out', derPath,
        '-outform', format,
      ];

      if (DEBUG) {
        console.log('openssl ' + args.join(' '));
      }
      return openssl(args).then(function() {
        var csr = fs.readFileSync(derPath);
        fs.unlinkSync(csrPath);
        fs.unlinkSync(derPath);
        return csr;
      }, function(error) {
        fs.unlinkSync(csrPath);
        fs.unlinkSync(derPath);
        throw error;
      });
    }, function(error) {
      confPath && fs.unlinkSync(confPath);
      fs.unlinkSync(keyPath);
      throw error;
    });
  };

  function subjectString(domain, options) {
    var parts = ['/CN=', domain];
    if (options) {
      for (var key in subjectKeys) {
        if (options.hasOwnProperty(key)) {
          parts.push('/' + subjectKeys[key] + '=' + options[key]);
        }
      }
      if (options.email) {
        parts.unshift('/emailAddress=', options.email);
      }
    }
    return parts.join('');
  }

  function createSSLConfig(confPath, domains, options) {
    var parts = [
      '[ req ]',
      'default_bits=2048',
      'prompt=no',
      'default_md=sha256',
      'req_extensions=v3_req',
      'distinguished_name=dn',
      '',
      '[ dn ]',
      'CN=' + domains[0],
    ];
    if (options) {
      for (var key in subjectKeys) {
        if (options.hasOwnProperty(key)) {
          parts.push(subjectKeys[key] + '=' + options[key]);
        }
      }
      if (options.email) {
        parts.push('emailAddress=' + options.email);
      }
    }
    parts.push(
      '[ v3_req ]',
      'subjectAltName=@alt_names',
      '',
      '[ alt_names ]'
    );
    domains.forEach(function(domain, index) {
      parts.push('DNS.' + (index + 1) + '=' + domain);
    });
    return parts.join('\n');
  }
})();

function openssl(args) {
  return new Promise(function(resolve, reject) {
    var proc = spawn('openssl', args);
    proc.on('error', reject);
    proc.on('exit', resolve);
  });
}

function tempPath() {
  return path.join(os.tmpdir(), Math.random().toString(16).slice(2));
}

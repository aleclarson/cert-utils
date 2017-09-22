
var assertValid = require('assertValid');
var spawn = require('child_process').spawn;
var path = require('path');
var fs = require('fs');
var os = require('os');

var optionTypes = {
  key: 'string',
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

module.exports = function generateCsr(options) {
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

  var reqPath = tempPath();
  var keyPath = tempPath();

  // Store the private key in a temporary file.
  fs.writeFileSync(keyPath, options.key);

  var args = [
    'req',
    '-new',
    '-nodes',
    '-out', reqPath,
    '-key', keyPath,
  ];

  if (domains.length > 1) {
    var confPath = tempPath();
    fs.writeFileSync(confPath, createSSLConfig(confPath, domains, options.subject));
    args.push('-config', confPath);
  } else {
    args.push('-subj', subjectString(domains[0], options.subject));
  }

  // Create the CSR.
  return openssl(args).then(function() {
    try {
      var csr = fs.readFileSync(reqPath);
    } catch(error) {
      throw Error('Failed to generate CSR');
    }

    // Remove temporary files.
    fs.unlinkSync(reqPath);
    fs.unlinkSync(keyPath);
    confPath && fs.unlinkSync(confPath);

    return csr;
  });
};

module.exports.subjectTypes = optionTypes.subject;

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

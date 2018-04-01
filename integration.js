let async = require('async');
let config = require('./config/config');

let Logger;
let requestOptions = {};

function getRequestOptions() {
    return JSON.parse(JSON.stringify(requestOptions));
}

function doLookup(entities, options, callback) {
    let results = [];

    async.each(entities, (entity, done) => {
        let requestOptions = getRequestOptions();
        requestOptions.url = 'https://caws3.nsslabs.com/graphql';
        requestOptions.method = 'POST';
        requestOptions.headers = {
            Authorization: options.apiKey
        };
        requestOptions.body = {
            query: `query { 
                threatInfo(ipAddresses: ["${entity.value}"]) {
                    exploits {
                        nssid
                    }
                }
            }`
        };

        request(requestOptions, (err, resp, body) => {
            if (err || resp.statusCode != 200) {
                Logger.error({ err: err, body: body });
                done(err || new Error('resp code was not 200 ' + body))
            }

            let threatInfo = body.data.threatInfo;
            if (threatInfo.exploits.length === 0) {
                results.push({
                    entity: entity,
                    data: null
                });
                done();
            } else {
                async.each(body.data.threatInfo.exploits, (exploit, done) => {
                    requestOptions.body = {
                        query: `query {
                            threatIntel(nssid: ${exploit.nssid}) {
                                details {
                                    exploitType
                                    discoveryDate
                                    threatType
                                    url
                                    md5FileHash
                                    application {
                                        daysAtRisk
                                        application {
                                            name
                                            family
                                            vendor {
                                                name
                                            }
                                        }
                                    }
                                    platform {
                                        daysAtRisk
                                        platform {
                                            name
                                            family
                                            vendor {
                                                name
                                            }
                                        }
                                    }
                                    browser {
                                        daysAtRisk
                                        browser {
                                            name
                                            family
                                            vendor {
                                                name
                                            }
                                        }
                                    }
                                    source {
                                        exploitType
                                        discoveryDate
                                        threatType
                                        device {
                                            name
                                            type
                                            vendor {
                                                name
                                            }
                                        }
                                    }
                                }
                            }
                        }`
                    };
                    request(requestOptions, (err, resp, body) => {
                        if (err || resp.statusCode != 200) {
                            Logger.error({ err: err, body: body });
                            done(err || new Error('resp code was not 200 ' + body))
                        }

                        Logger.trace({ body: body });
                        done();
                    });
                });
            }
        });
    }, err => {
        callback(err, results);
    });
}

function startup(logger) {
    Logger = logger;

    if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
        requestOptions.cert = fs.readFileSync(config.request.cert);
    }

    if (typeof config.request.key === 'string' && config.request.key.length > 0) {
        requestOptions.key = fs.readFileSync(config.request.key);
    }

    if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
        requestOptions.passphrase = config.request.passphrase;
    }

    if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
        requestOptions.ca = fs.readFileSync(config.request.ca);
    }

    if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
        requestOptions.proxy = config.request.proxy;
    }

    if (typeof config.request.rejectUnauthorized === 'boolean') {
        requestOptions.rejectUnauthorized = config.request.rejectUnauthorized;
    }
}

function validateOptions(options, callback) {
    let errors = [];

    if (typeof options.apiKey.value !== 'string' ||
        (typeof options.apiKey.value === 'string' && options.apiKey.value.length === 0)) {
        errors.push({
            key: "apiKey",
            message: errMessage
        });
    }

    callback(null, errors);
}

module.exports = {
    doLookup: doLookup,
    startup: startup,
    validateOptions: validateOptions
};

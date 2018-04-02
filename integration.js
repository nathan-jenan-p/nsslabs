let async = require('async');
let config = require('./config/config');
let request = require('request');

let Logger;
let requestOptions = {};

// TODO make this a request.default thingy
function getRequestOptions() {
    return JSON.parse(JSON.stringify(requestOptions));
}

function doLookup(entities, options, callback) {
    Logger.trace('starting lookup');
    let results = [];

    async.each(entities, (entity, done) => {
        let requestOptions = getRequestOptions();
        requestOptions.url = 'https://caws3.nsslabs.com/graphql';
        requestOptions.method = 'POST';
        requestOptions.headers = {
            Authorization: `Bearer ${options.apiKey}`
        };
        requestOptions.json = true;
        requestOptions.body = { // TODO make the date range dynamic
            query: `query { 
                threatInfo(ipAddresses: ["${entity.value}"] start: "2018-02-01" end: "2018-03-01") {
                    exploits {
                        nssid
                    }
                }
            }`
        };

        Logger.trace({ requestOptions: requestOptions });

        request(requestOptions, (err, resp, body) => {
            if (err || resp.statusCode != 200) {
                Logger.error({ err: err, body: body });
                done(err || new Error('resp code was not 200 ' + body));
                return;
            }

            Logger.trace('got response now looking up nssids');

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
                            threatIntel(nssid: "${exploit.nssid}") {
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
                                }
                            }
                        }`
                    };
                    request(requestOptions, (err, resp, body) => {
                        if (err || resp.statusCode != 200) {
                            Logger.error({ err: err, body: body });
                            done(err || new Error('resp code was not 200 ' + body));
                            return;
                        }

                        Logger.trace('got response now add nssids to result');

                        results.push({
                            entity: entity,
                            data: {
                                summary: ['test'],
                                details: body.data.threatIntel.details
                            }
                        });
                        done();
                    });
                }, err => {
                    done(err);
                });
            }
        });
    }, err => {
        Logger.trace({ resultsLength: results.length }, 'results sent to client');
        callback(err, results);
    });
}

function startup(logger) {
    Logger = logger;
    Logger.trace('starting startup');

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
    Logger.trace('starting validate');
    let errors = [];

    if (typeof options.apiKey.value !== 'string' ||
        (typeof options.apiKey.value === 'string' && options.apiKey.value.length === 0)) {
        errors.push({
            key: "apiKey",
            message: "API Key must be set"
        });
    }

    callback(null, errors);
}

module.exports = {
    doLookup: doLookup,
    startup: startup,
    validateOptions: validateOptions
};

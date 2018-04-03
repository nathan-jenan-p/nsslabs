let async = require('async');
let config = require('./config/config');
let request = require('request');
let moment = require('moment');

const DATE_FORMAT = 'YYYY-MM-DD'; //2018-02-01

let Logger;
let requestOptions = {};
let requestWithDefaults;

function doLookup(entities, options, callback) {
    Logger.trace('starting lookup');
    let results = [];

    async.each(entities, (entity, done) => {
        let startDate = moment().subtract(options.range, 'days').format(DATE_FORMAT)
        let endDate = moment().format(DATE_FORMAT);

        let requestOptions = {};
        requestOptions.url = 'https://caws3.nsslabs.com/graphql';
        requestOptions.method = 'POST';
        requestOptions.headers = {
            Authorization: `Bearer ${options.apiKey}`
        };
        requestOptions.json = true;

        if (entity.isIP) {
            requestOptions.body = {
                query: `query { 
                threatInfo(ipAddresses: ["${entity.value}"] start: "${startDate}" end: "${endDate}") {
                    exploits {
                        nssid
                    }
                }
            }`
            };
        } else {
            results.push({
                entity: entity,
                data: null
            });
            done();
            return;
        }

        Logger.trace({ requestOptions: requestOptions });

        requestWithDefaults(requestOptions, (err, resp, body) => {
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
                                nssid
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
                    requestWithDefaults(requestOptions, (err, resp, body) => {
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
                                details: body.data.threatIntel
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

    requestWithDefaults = request.defaults(requestOptions);
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

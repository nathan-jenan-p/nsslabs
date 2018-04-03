polarity.export = PolarityComponent.extend({
    details: Ember.computed.alias('block.data.details.details'),
    nssid: Ember.computed.alias('block.data.details.nssid')
});

polarity.export = PolarityComponent.extend({
    details: Ember.computed.alias('block.data.details'),
    tags: Ember.computed('block.data.details', function () {
        let details = this.get('block.data.details');

        return [details.exploitType, details.threatType];
    })
});

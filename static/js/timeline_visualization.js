class TimelineVisualization {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.timeline = null;
        this.data = [];
    }

    initialize() {
        this.timeline = new vis.Timeline(this.container, new vis.DataSet(), {
            height: '400px',
            showCurrentTime: false,
            stack: true,
            zoomable: true,
            groupTemplate: function(group) {
                return `<div class="timeline-group">
                    <div class="timeline-group-name">${group.content}</div>
                    <div class="timeline-group-type">${group.tacticType}</div>
                </div>`;
            }
        });
    }

    updateData(huntResults) {
        const items = [];
        const groups = new Set();

        huntResults.forEach((result, idx) => {
            const timestamp = new Date(result.timestamp);
            const group = result.tactic || 'Uncategorized';
            groups.add(group);

            items.push({
                id: idx,
                content: result.description,
                start: timestamp,
                group: group,
                className: `suspicion-level-${result.suspicionLevel}`,
                title: `Score: ${result.suspicionScore}<br>Details: ${result.details}`
            });
        });

        const groupsArray = Array.from(groups).map(group => ({
            id: group,
            content: group,
            tacticType: 'MITRE ATT&CK'
        }));

        this.timeline.setData({
            items: new vis.DataSet(items),
            groups: new vis.DataSet(groupsArray)
        });
    }

    addCorrelatedEvents(events) {
        const items = this.timeline.getItems();
        events.forEach(event => {
            items.add({
                id: `corr_${event.id}`,
                content: event.description,
                start: new Date(event.timestamp),
                group: event.tactic,
                className: 'correlated-event'
            });
        });
    }
}
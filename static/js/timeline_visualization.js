function createTimeline(data) {
    const container = document.getElementById('timeline-container');
    container.innerHTML = '';

    // Group events by tactic
    const groupedEvents = {};
    data.forEach(event => {
        const tactic = event.mitre_tactic || 'Unknown';
        if (!groupedEvents[tactic]) {
            groupedEvents[tactic] = [];
        }
        groupedEvents[tactic].push(event);
    });

    // Create timeline groups
    const groups = Object.keys(groupedEvents).map((tactic, index) => ({
        id: index,
        content: tactic,
        nestedGroups: [],
        showNested: false
    }));

    // Create timeline items
    const items = [];
    let itemId = 0;
    Object.entries(groupedEvents).forEach(([tactic, events], groupIndex) => {
        events.forEach(event => {
            items.push({
                id: itemId++,
                group: groupIndex,
                content: event.description || event.type,
                start: new Date(event._time),
                title: JSON.stringify(event, null, 2),
                className: `event-${event.severity || 'info'}`
            });
        });
    });

    // Initialize timeline
    const timeline = new vis.Timeline(container, new vis.DataSet(items), {
        groupOrder: 'content',
        orientation: 'top',
        stack: true,
        zoomable: true,
        groupEditable: false,
        editable: false
    });

    // Add click handlers
    timeline.on('select', function(properties) {
        if (properties.items.length) {
            const item = items.find(i => i.id === properties.items[0]);
            showEventDetails(item);
        }
    });
}

function showEventDetails(item) {
    const modal = document.getElementById('event-details-modal');
    const content = document.getElementById('event-details-content');
    content.innerHTML = `<pre>${item.title}</pre>`;
    new bootstrap.Modal(modal).show();
}
function addFeedbackControls(container, data) {
    const controls = document.createElement('div');
    controls.className = 'feedback-controls';
    
    // Add field exclusion
    const fieldSelect = document.createElement('select');
    fieldSelect.multiple = true;
    Object.keys(data.fields || {}).forEach(field => {
        const option = document.createElement('option');
        option.value = field;
        option.text = field;
        fieldSelect.appendChild(option);
    });

    // Add exclude button
    const excludeBtn = document.createElement('button');
    excludeBtn.textContent = 'Exclude Selected';
    excludeBtn.onclick = () => {
        const selectedFields = Array.from(fieldSelect.selectedOptions).map(opt => opt.value);
        submitFeedback({
            hunt_id: data.hunt_id,
            exclude_fields: selectedFields
        });
    };

    controls.appendChild(fieldSelect);
    controls.appendChild(excludeBtn);
    container.appendChild(controls);
}

function submitFeedback(feedback) {
    fetch('/api/hunt/refine', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(feedback)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            location.reload();
        }
    });
}

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
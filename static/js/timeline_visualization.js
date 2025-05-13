class TimelineVisualization {
    constructor(container) {
        this.container = container;
        this.timeline = null;
    }

    render(data) {
        // Clear previous visualization
        this.container.innerHTML = '';

        const timelineDiv = document.createElement('div');
        timelineDiv.className = 'attack-timeline';

        // Create timeline sections for each tactic
        Object.entries(data.tactics).forEach(([tactic, events]) => {
            const tacticSection = this._createTacticSection(tactic, events);
            timelineDiv.appendChild(tacticSection);
        });

        this.container.appendChild(timelineDiv);
    }

    _createTacticSection(tactic, events) {
        const section = document.createElement('div');
        section.className = 'timeline-section';

        const header = document.createElement('h3');
        header.textContent = tactic;
        section.appendChild(header);

        const eventList = document.createElement('ul');
        eventList.className = 'timeline-events';

        events.forEach(event => {
            const eventItem = this._createEventItem(event);
            eventList.appendChild(eventItem);
        });

        section.appendChild(eventList);
        return section;
    }

    _createEventItem(event) {
        const item = document.createElement('li');
        item.className = 'timeline-event';

        const time = document.createElement('span');
        time.className = 'event-time';
        time.textContent = new Date(event._time).toLocaleString();

        const description = document.createElement('span');
        description.className = 'event-description';
        description.textContent = event._raw;

        item.appendChild(time);
        item.appendChild(description);

        // Add click handler for pivoting
        item.addEventListener('click', () => this._pivotToEvent(event));

        return item;
    }

    _pivotToEvent(event) {
        // Implement pivot logic
        console.log('Pivot to event:', event);
        // Trigger a new hunt based on selected event attributes
    }
}

function createTimelineVisualization(data, options = {}) {
    const {
        showLayered = true,
        collapseThreshold = 200,
        maxSuspicionScore = 100
    } = options;

    // Create the timeline visualization with layers
    const container = document.getElementById('timeline-container');
    const layerContainer = showLayered ? createLayerContainer() : null;
}
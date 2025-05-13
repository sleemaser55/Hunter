
class TimelineVisualization {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.timelineData = null;
    }

    render(data) {
        this.timelineData = data;
        this.container.innerHTML = '';

        const timeline = document.createElement('div');
        timeline.className = 'timeline';

        // Create timeline entries for each tactic
        Object.entries(data.timeline).forEach(([tactic, events]) => {
            const tacticGroup = this.createTacticGroup(tactic, events);
            timeline.appendChild(tacticGroup);
        });

        this.container.appendChild(timeline);
    }

    createTacticGroup(tactic, events) {
        const group = document.createElement('div');
        group.className = 'timeline-group';

        const header = document.createElement('h3');
        header.textContent = tactic;
        group.appendChild(header);

        events.forEach(event => {
            const eventEl = this.createEventElement(event);
            group.appendChild(eventEl);
        });

        return group;
    }

    createEventElement(event) {
        const el = document.createElement('div');
        el.className = 'timeline-event';
        el.dataset.suspicionScore = event.suspicion_score || 0;

        const time = document.createElement('div');
        time.className = 'event-time';
        time.textContent = new Date(event.timestamp).toLocaleString();

        const desc = document.createElement('div');
        desc.className = 'event-description';
        desc.textContent = event.description;

        const score = document.createElement('div');
        score.className = 'event-score';
        score.textContent = `Score: ${Math.round((event.suspicion_score || 0) * 100)}%`;

        el.appendChild(time);
        el.appendChild(desc);
        el.appendChild(score);

        // Add click handler for pivoting
        el.addEventListener('click', () => this.handleEventClick(event));

        return el;
    }

    handleEventClick(event) {
        // Emit custom event for pivot handling
        const pivotEvent = new CustomEvent('timelinePivot', {
            detail: {
                event: event,
                type: 'timeline'
            }
        });
        document.dispatchEvent(pivotEvent);
    }

    filterBySuspicionScore(minScore) {
        const events = this.container.querySelectorAll('.timeline-event');
        events.forEach(event => {
            const score = parseFloat(event.dataset.suspicionScore);
            event.style.display = score >= minScore ? 'block' : 'none';
        });
    }
}

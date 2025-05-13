
// Timeline visualization using vis.js Timeline
class TimelineVisualization {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.timeline = null;
        this.data = null;
    }

    init(timelineData) {
        this.data = timelineData;
        
        // Create items for timeline
        const items = new vis.DataSet(
            this.data.nodes.map(node => ({
                id: node.id,
                content: node.label,
                title: `${node.tactic}: ${node.technique}<br>Score: ${node.score}`,
                start: node.details.timestamp,
                group: node.tactic,
                className: `suspicion-${Math.floor(node.score/20)}`
            }))
        );

        // Create groups for tactics
        const groups = new vis.DataSet(
            [...new Set(this.data.nodes.map(n => n.tactic))].map(tactic => ({
                id: tactic,
                content: tactic
            }))
        );

        // Configuration
        const options = {
            height: '400px',
            verticalScroll: true,
            zoomKey: 'ctrlKey',
            orientation: 'both'
        };

        // Initialize timeline
        this.timeline = new vis.Timeline(
            this.container,
            items,
            groups,
            options
        );
    }

    highlightPhase(phase) {
        if (!this.data) return;
        
        const phaseEvents = this.data.phases.find(p => p.name === phase);
        if (phaseEvents) {
            this.timeline.setSelection(phaseEvents.events);
        }
    }

    setWindow(start, end) {
        this.timeline.setWindow(start, end);
    }
}

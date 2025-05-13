
class TimelineVisualization {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.timeline = null;
        this.data = null;
        this.options = {
            height: '400px',
            verticalScroll: true,
            zoomKey: 'ctrlKey',
            orientation: 'both',
            showMajorLabels: true,
            showCurrentTime: true,
            stack: true
        };
    }

    init(timelineData) {
        this.data = timelineData;
        
        // Create items for timeline with correlation indicators
        const items = new vis.DataSet(
            this.data.nodes.map(node => ({
                id: node.id,
                content: this._createNodeContent(node),
                title: this._createNodeTooltip(node),
                start: node.details.timestamp,
                group: node.tactic,
                className: `suspicion-${Math.floor(node.score/20)} ${this._getCorrelationClass(node.id)}`
            }))
        );

        // Create groups for tactics
        const groups = new vis.DataSet(
            [...new Set(this.data.nodes.map(n => n.tactic))].map(tactic => ({
                id: tactic,
                content: tactic,
                title: `Events grouped by ${tactic}`
            }))
        );

        // Initialize timeline
        this.timeline = new vis.Timeline(
            this.container,
            items,
            groups,
            this.options
        );

        // Add correlation lines
        this._drawCorrelations();
    }

    _createNodeContent(node) {
        return `
            <div class="timeline-node">
                <span class="node-title">${node.label}</span>
                <span class="node-score">Score: ${node.score}</span>
            </div>
        `;
    }

    _createNodeTooltip(node) {
        return `
            ${node.tactic}: ${node.technique}<br>
            Score: ${node.score}<br>
            ${Object.entries(node.details)
                .filter(([k,v]) => k !== 'timestamp')
                .map(([k,v]) => `${k}: ${v}`)
                .join('<br>')}
        `;
    }

    _getCorrelationClass(nodeId) {
        const correlations = this.data.correlations.filter(
            c => c.source === nodeId || c.target === nodeId
        );
        return correlations.length > 0 ? 'has-correlation' : '';
    }

    _drawCorrelations() {
        if (!this.data.correlations) return;
        
        const container = this.container.querySelector('.vis-timeline');
        const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        svg.classList.add('correlation-lines');
        container.appendChild(svg);

        this.data.correlations.forEach(correlation => {
            const sourcePos = this._getNodePosition(correlation.source);
            const targetPos = this._getNodePosition(correlation.target);
            
            if (sourcePos && targetPos) {
                const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
                line.setAttribute('x1', sourcePos.x);
                line.setAttribute('y1', sourcePos.y);
                line.setAttribute('x2', targetPos.x);
                line.setAttribute('y2', targetPos.y);
                line.setAttribute('class', `correlation-line score-${Math.floor(correlation.score * 10)}`);
                svg.appendChild(line);
            }
        });
    }

    _getNodePosition(nodeId) {
        const element = this.container.querySelector(`[data-id="${nodeId}"]`);
        if (!element) return null;
        
        const rect = element.getBoundingClientRect();
        const containerRect = this.container.getBoundingClientRect();
        
        return {
            x: rect.left - containerRect.left + rect.width/2,
            y: rect.top - containerRect.top + rect.height/2
        };
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

    redraw() {
        this.timeline.redraw();
        this._drawCorrelations();
    }
}

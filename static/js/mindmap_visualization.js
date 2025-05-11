/**
 * MindMap Visualization - JavaScript module for rendering interactive mind maps
 * This module provides functionality to:
 * 1. Render D3.js-based mind map visualizations
 * 2. Interact with nodes via dragging, zooming, and clicking
 * 3. Display different node types (results, fields, values, techniques)
 * 4. Support pivoting based on field values
 */

class MindMapVisualization {
    constructor(containerId) {
        this.containerId = containerId;
        this.container = document.getElementById(containerId);
        this.width = 0;
        this.height = 0;
        this.svg = null;
        this.simulation = null;
        this.nodes = [];
        this.links = [];
        this.fieldPivot = null;
    }

    /**
     * Initialize the mind map visualization
     * @param {Object} data - Object containing nodes and links
     * @param {Object} fieldPivot - FieldPivot instance for handling pivot interactions
     */
    init(data, fieldPivot) {
        if (!this.container) {
            console.error(`Container with ID "${this.containerId}" not found`);
            return;
        }

        // Store field pivot instance
        this.fieldPivot = fieldPivot;

        // Get container dimensions
        this.width = this.container.clientWidth;
        this.height = this.container.clientHeight || 600;

        // Clear any existing content
        this.container.innerHTML = '';

        // Set up SVG
        this.svg = d3.select(`#${this.containerId}`)
            .append('svg')
            .attr('width', this.width)
            .attr('height', this.height);

        // Set up groups for links and nodes
        const g = this.svg.append('g');
        const linkGroup = g.append('g').attr('class', 'links');
        const nodeGroup = g.append('g').attr('class', 'nodes');

        // Set up zoom behavior
        const zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on('zoom', (event) => {
                g.attr('transform', event.transform);
            });

        this.svg.call(zoom);

        // Center the view
        this.svg.call(zoom.transform, d3.zoomIdentity.translate(this.width / 2, this.height / 2));

        // Store nodes and links
        this.nodes = data.nodes || [];
        this.links = data.links || [];

        // Create the simulation
        this.simulation = d3.forceSimulation()
            .force('link', d3.forceLink().id(d => d.id).distance(100))
            .force('charge', d3.forceManyBody().strength(-300))
            .force('center', d3.forceCenter(0, 0))
            .force('collide', d3.forceCollide(30));

        // Create the links
        const links = linkGroup
            .selectAll('line')
            .data(this.links)
            .enter()
            .append('line')
            .attr('class', 'link')
            .style('stroke-width', d => d.value || 1);

        // Create the nodes
        const nodes = nodeGroup
            .selectAll('.node')
            .data(this.nodes)
            .enter()
            .append('g')
            .attr('class', d => `node ${d.group}`)
            .call(d3.drag()
                .on('start', this.dragStarted.bind(this))
                .on('drag', this.dragged.bind(this))
                .on('end', this.dragEnded.bind(this)));

        // Add circles to nodes
        nodes.append('circle')
            .attr('r', d => this.getNodeRadius(d))
            .style('fill', d => this.getNodeColor(d));

        // Add text to nodes
        nodes.append('text')
            .attr('dx', 15)
            .attr('dy', 5)
            .text(d => d.label)
            .style('font-weight', d => d.group === 'root' ? 'bold' : 'normal');

        // Handle clicks on nodes
        nodes.on('click', (event, d) => this.handleNodeClick(event, d));

        // Add tooltips
        nodes.append('title')
            .text(d => d.label);

        // Start the simulation
        this.simulation
            .nodes(this.nodes)
            .on('tick', () => this.ticked(links, nodes));

        this.simulation.force('link')
            .links(this.links);
    }

    /**
     * Get the radius for a node based on its type
     * @param {Object} node - The node data
     * @returns {number} - The radius in pixels
     */
    getNodeRadius(node) {
        switch (node.group) {
            case 'root':
                return 20;
            case 'technique':
                return 15;
            case 'result':
                return 12;
            default:
                return 8;
        }
    }

    /**
     * Get the color for a node based on its type and properties
     * @param {Object} node - The node data
     * @returns {string} - The color as a CSS color string
     */
    getNodeColor(node) {
        if (node.group === 'technique') {
            // Color based on confidence score if available
            const score = node.score || 0;
            if (score >= 0.7) return 'var(--bs-danger)'; // High match
            if (score >= 0.4) return 'var(--bs-warning)'; // Medium match
            return 'var(--bs-info)'; // Low match
        }

        // Default colors based on node group
        switch (node.group) {
            case 'root':
                return 'var(--bs-primary)';
            case 'result':
                return 'var(--bs-success)';
            case 'field':
                return 'var(--bs-warning)';
            case 'value':
                return 'var(--bs-light)';
            default:
                return 'var(--bs-secondary)';
        }
    }

    /**
     * Handle click events on nodes
     * @param {Event} event - The click event
     * @param {Object} node - The node data
     */
    handleNodeClick(event, node) {
        // Handle value nodes for pivoting
        if (node.group === 'value' && node.field && this.fieldPivot) {
            this.fieldPivot.openPivotModal(node.field, node.label);
        }

        // Handle technique nodes for opening MITRE ATT&CK information
        if (node.group === 'technique' && node.id) {
            const techniqueId = node.id.replace('technique_', '');
            window.open(`https://attack.mitre.org/techniques/${techniqueId.replace('T', '')}`, '_blank');
        }
    }

    /**
     * Update node and link positions on simulation tick
     * @param {d3.Selection} links - D3 selection of link elements
     * @param {d3.Selection} nodes - D3 selection of node elements
     */
    ticked(links, nodes) {
        links
            .attr('x1', d => d.source.x)
            .attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x)
            .attr('y2', d => d.target.y);

        nodes
            .attr('transform', d => `translate(${d.x},${d.y})`);
    }

    /**
     * Handle drag start event
     * @param {Event} event - The drag event
     * @param {Object} d - The node data
     */
    dragStarted(event, d) {
        if (!event.active) this.simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }

    /**
     * Handle drag event
     * @param {Event} event - The drag event
     * @param {Object} d - The node data
     */
    dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }

    /**
     * Handle drag end event
     * @param {Event} event - The drag event
     * @param {Object} d - The node data
     */
    dragEnded(event, d) {
        if (!event.active) this.simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }

    /**
     * Resize the visualization
     */
    resize() {
        if (!this.svg) return;

        // Get new container dimensions
        this.width = this.container.clientWidth;
        this.height = this.container.clientHeight || 600;

        // Update SVG dimensions
        this.svg
            .attr('width', this.width)
            .attr('height', this.height);

        // Center the simulation
        if (this.simulation) {
            this.simulation.force('center', d3.forceCenter(0, 0));
            this.simulation.alpha(0.3).restart();
        }
    }
}

// Export as global variable
window.MindMapVisualization = MindMapVisualization;
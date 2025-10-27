let currentCampaignId = null;
let cy = null;

document.addEventListener('DOMContentLoaded', function() {
    loadHosts();
    loadCampaigns();
    updateStats();
    
    document.getElementById('hostForm').addEventListener('submit', handleHostSubmit);
    document.getElementById('campaignForm').addEventListener('submit', handleCampaignSubmit);
    document.getElementById('hostCancelBtn').addEventListener('click', cancelHostEdit);
    document.getElementById('refreshVizBtn').addEventListener('click', refreshVisualization);
    document.getElementById('downloadReportBtn').addEventListener('click', downloadReport);
    
    document.getElementById('vizCampaignSelect').addEventListener('change', function(e) {
        currentCampaignId = e.target.value;
        if (currentCampaignId) {
            loadVisualization(currentCampaignId);
        }
    });
    
    document.getElementById('logsCampaignSelect').addEventListener('change', function(e) {
        currentCampaignId = e.target.value;
        if (currentCampaignId) {
            loadLogs(currentCampaignId);
        }
    });
});

async function loadHosts() {
    try {
        const response = await fetch('/api/hosts');
        const hosts = await response.json();
        
        const tbody = document.getElementById('hostsTable');
        const initialHostSelect = document.getElementById('campaignInitialHost');
        
        if (hosts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No hosts configured. Add hosts to begin.</td></tr>';
            initialHostSelect.innerHTML = '<option value="">Random</option>';
            return;
        }
        
        tbody.innerHTML = hosts.map(host => `
            <tr>
                <td class="code-font">${escapeHtml(host.name)}</td>
                <td class="code-font">${escapeHtml(host.ip_address)}</td>
                <td>${escapeHtml(host.os)}</td>
                <td><span class="badge bg-secondary">${host.open_ports.length} ports</span></td>
                <td><span class="badge bg-warning">${host.vulnerabilities.length} CVEs</span></td>
                <td><span class="badge badge-criticality-${host.criticality}">${getCriticalityLabel(host.criticality)}</span></td>
                <td>
                    <button class="btn btn-sm btn-info" onclick="editHost(${host.id})">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteHost(${host.id})">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            </tr>
        `).join('');
        
        initialHostSelect.innerHTML = '<option value="">Random</option>' + 
            hosts.map(h => `<option value="${h.id}">${escapeHtml(h.name)} (${escapeHtml(h.ip_address)})</option>`).join('');
        
    } catch (error) {
        console.error('Error loading hosts:', error);
    }
}

async function loadCampaigns() {
    try {
        const response = await fetch('/api/campaigns');
        const campaigns = await response.json();
        
        const tbody = document.getElementById('campaignsTable');
        const vizSelect = document.getElementById('vizCampaignSelect');
        const logsSelect = document.getElementById('logsCampaignSelect');
        
        if (campaigns.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No campaigns executed yet.</td></tr>';
            vizSelect.innerHTML = '<option value="">Select Campaign...</option>';
            logsSelect.innerHTML = '<option value="">Select Campaign...</option>';
            return;
        }
        
        tbody.innerHTML = campaigns.map(campaign => `
            <tr>
                <td class="code-font">${campaign.id}</td>
                <td>${escapeHtml(campaign.name)}</td>
                <td class="code-font">${campaign.seed}</td>
                <td><span class="badge ${campaign.status === 'completed' ? 'bg-success' : 'bg-warning'}">${campaign.status}</span></td>
                <td>${new Date(campaign.created_at).toLocaleString()}</td>
                <td>
                    <button class="btn btn-sm btn-info" onclick="viewCampaign(${campaign.id})">
                        <i class="fas fa-eye"></i> View
                    </button>
                </td>
            </tr>
        `).join('');
        
        const optionsHtml = campaigns.map(c => 
            `<option value="${c.id}">${escapeHtml(c.name)} (ID: ${c.id})</option>`
        ).join('');
        
        vizSelect.innerHTML = '<option value="">Select Campaign...</option>' + optionsHtml;
        logsSelect.innerHTML = '<option value="">Select Campaign...</option>' + optionsHtml;
        
    } catch (error) {
        console.error('Error loading campaigns:', error);
    }
}

async function handleHostSubmit(e) {
    e.preventDefault();
    
    const hostId = document.getElementById('hostId').value;
    const ports = document.getElementById('hostPorts').value
        .split(',')
        .map(p => p.trim())
        .filter(p => p);
    
    const vulnsSelect = document.getElementById('hostVulns');
    const selectedVulns = Array.from(vulnsSelect.selectedOptions).map(opt => opt.value);
    
    const hostData = {
        name: document.getElementById('hostName').value,
        ip_address: document.getElementById('hostIp').value,
        os: document.getElementById('hostOs').value,
        open_ports: ports,
        vulnerabilities: selectedVulns,
        criticality: parseInt(document.getElementById('hostCriticality').value)
    };
    
    try {
        const url = hostId ? `/api/hosts/${hostId}` : '/api/hosts';
        const method = hostId ? 'PUT' : 'POST';
        
        const response = await fetch(url, {
            method: method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(hostData)
        });
        
        if (response.ok) {
            document.getElementById('hostForm').reset();
            document.getElementById('hostId').value = '';
            document.getElementById('hostSubmitBtn').innerHTML = '<i class="fas fa-save me-2"></i>Add Host';
            document.getElementById('hostCancelBtn').style.display = 'none';
            loadHosts();
            updateStats();
        } else {
            const error = await response.json();
            alert('Error: ' + error.error);
        }
    } catch (error) {
        console.error('Error saving host:', error);
        alert('Failed to save host');
    }
}

async function editHost(id) {
    try {
        const response = await fetch('/api/hosts');
        const hosts = await response.json();
        const host = hosts.find(h => h.id === id);
        
        if (!host) return;
        
        document.getElementById('hostId').value = host.id;
        document.getElementById('hostName').value = host.name;
        document.getElementById('hostIp').value = host.ip_address;
        document.getElementById('hostOs').value = host.os;
        document.getElementById('hostPorts').value = host.open_ports.join(', ');
        document.getElementById('hostCriticality').value = host.criticality;
        
        const vulnsSelect = document.getElementById('hostVulns');
        Array.from(vulnsSelect.options).forEach(opt => {
            opt.selected = host.vulnerabilities.includes(opt.value);
        });
        
        document.getElementById('hostSubmitBtn').innerHTML = '<i class="fas fa-save me-2"></i>Update Host';
        document.getElementById('hostCancelBtn').style.display = 'block';
        
        document.getElementById('hostName').scrollIntoView({ behavior: 'smooth' });
    } catch (error) {
        console.error('Error loading host:', error);
    }
}

function cancelHostEdit() {
    document.getElementById('hostForm').reset();
    document.getElementById('hostId').value = '';
    document.getElementById('hostSubmitBtn').innerHTML = '<i class="fas fa-save me-2"></i>Add Host';
    document.getElementById('hostCancelBtn').style.display = 'none';
}

async function deleteHost(id) {
    if (!confirm('Are you sure you want to delete this host?')) return;
    
    try {
        const response = await fetch(`/api/hosts/${id}`, { method: 'DELETE' });
        if (response.ok) {
            loadHosts();
            updateStats();
        }
    } catch (error) {
        console.error('Error deleting host:', error);
    }
}

async function handleCampaignSubmit(e) {
    e.preventDefault();
    
    const campaignData = {
        name: document.getElementById('campaignName').value,
        description: document.getElementById('campaignDesc').value,
        initial_host_id: document.getElementById('campaignInitialHost').value || null,
        seed: document.getElementById('campaignSeed').value || null
    };
    
    try {
        const response = await fetch('/api/campaigns', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(campaignData)
        });
        
        if (response.ok) {
            const result = await response.json();
            const campaignId = result.id;
            
            alert(`Campaign created with seed ${result.seed}. Executing simulation...`);
            
            const execResponse = await fetch(`/api/campaigns/${campaignId}/execute`, {
                method: 'POST'
            });
            
            if (execResponse.ok) {
                const execResult = await execResponse.json();
                alert(`Campaign completed!\n\nTurns: ${execResult.turns}\nCompromised: ${execResult.compromised}/${execResult.total_hosts} hosts`);
                
                document.getElementById('campaignForm').reset();
                loadCampaigns();
                updateStats();
                
                const tabTrigger = new bootstrap.Tab(document.getElementById('logs-tab'));
                tabTrigger.show();
                
                document.getElementById('logsCampaignSelect').value = campaignId;
                loadLogs(campaignId);
            }
        }
    } catch (error) {
        console.error('Error creating campaign:', error);
        alert('Failed to create campaign');
    }
}

async function viewCampaign(id) {
    currentCampaignId = id;
    
    const logsTab = new bootstrap.Tab(document.getElementById('logs-tab'));
    logsTab.show();
    
    document.getElementById('logsCampaignSelect').value = id;
    loadLogs(id);
}

async function loadLogs(campaignId) {
    try {
        const response = await fetch(`/api/campaigns/${campaignId}/logs`);
        const logs = await response.json();
        
        const container = document.getElementById('logsContainer');
        
        if (logs.length === 0) {
            container.innerHTML = '<div class="text-center text-muted py-5">No logs available for this campaign.</div>';
            return;
        }
        
        container.innerHTML = logs.map(log => {
            const phaseClass = log.phase.toLowerCase().replace(/ /g, '-');
            const statusClass = log.success ? 'success' : 'failed';
            const statusText = log.success ? '✓ SUCCESS' : '✗ FAILED';
            const source = log.source_name || 'External';
            const target = log.target_name || 'Unknown';
            
            return `
                <div class="log-entry ${statusClass}">
                    <div class="log-turn">
                        Turn ${log.turn_number} 
                        <span class="log-phase ${phaseClass}">${log.phase}</span>
                        <span class="log-status ${statusClass}">${statusText}</span>
                    </div>
                    <div>
                        <span class="log-technique">${escapeHtml(log.technique)}</span>
                        <span class="log-mitre">(${log.mitre_id})</span>
                    </div>
                    <div class="log-details">
                        <strong>${escapeHtml(source)}</strong> → <strong>${escapeHtml(target)}</strong>
                    </div>
                    <div class="log-details">${escapeHtml(log.details)}</div>
                </div>
            `;
        }).join('');
        
    } catch (error) {
        console.error('Error loading logs:', error);
    }
}

async function loadVisualization(campaignId) {
    try {
        const [hostsResponse, logsResponse] = await Promise.all([
            fetch('/api/hosts'),
            fetch(`/api/campaigns/${campaignId}/logs`)
        ]);
        
        const hosts = await hostsResponse.json();
        const logs = await logsResponse.json();
        
        const compromisedHosts = new Set();
        let initialHostId = null;
        
        logs.forEach(log => {
            if (log.success) {
                if (log.phase === 'Initial Access') {
                    initialHostId = log.target_host_id;
                }
                compromisedHosts.add(log.target_host_id);
            }
        });
        
        const nodes = hosts.map(host => ({
            data: {
                id: `host-${host.id}`,
                label: host.name,
                ip: host.ip_address,
                compromised: compromisedHosts.has(host.id),
                initial: host.id === initialHostId
            }
        }));
        
        const edges = [];
        const edgeSet = new Set();
        
        logs.forEach(log => {
            if (log.success && log.source_host_id && log.target_host_id) {
                const edgeId = `${log.source_host_id}-${log.target_host_id}`;
                if (!edgeSet.has(edgeId)) {
                    edges.push({
                        data: {
                            id: edgeId,
                            source: `host-${log.source_host_id}`,
                            target: `host-${log.target_host_id}`
                        }
                    });
                    edgeSet.add(edgeId);
                }
            }
        });
        
        renderGraph(nodes, edges);
        
    } catch (error) {
        console.error('Error loading visualization:', error);
    }
}

function renderGraph(nodes, edges) {
    const container = document.getElementById('networkGraph');
    
    if (cy) {
        cy.destroy();
    }
    
    cy = cytoscape({
        container: container,
        elements: [...nodes, ...edges],
        style: [
            {
                selector: 'node',
                style: {
                    'background-color': function(ele) {
                        if (ele.data('initial')) return '#FF6B35';
                        return ele.data('compromised') ? '#E94560' : '#4CAF50';
                    },
                    'label': 'data(label)',
                    'color': '#FFFFFF',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'font-size': '12px',
                    'font-weight': 'bold',
                    'width': 60,
                    'height': 60,
                    'border-width': 2,
                    'border-color': '#FFFFFF'
                }
            },
            {
                selector: 'edge',
                style: {
                    'width': 2,
                    'line-color': '#E94560',
                    'target-arrow-color': '#E94560',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                    'opacity': 0.7
                }
            }
        ],
        layout: {
            name: 'cose',
            animate: true,
            animationDuration: 1000,
            idealEdgeLength: 100,
            nodeOverlap: 20,
            refresh: 20,
            fit: true,
            padding: 30,
            randomize: false,
            componentSpacing: 100,
            nodeRepulsion: 400000,
            edgeElasticity: 100,
            nestingFactor: 5,
            gravity: 80
        }
    });
    
    cy.on('tap', 'node', function(evt) {
        const node = evt.target;
        const data = node.data();
        alert(`Host: ${data.label}\nIP: ${data.ip}\nStatus: ${data.compromised ? 'COMPROMISED' : 'SECURE'}`);
    });
}

function refreshVisualization() {
    const campaignId = document.getElementById('vizCampaignSelect').value;
    if (campaignId) {
        loadVisualization(campaignId);
    } else {
        alert('Please select a campaign first');
    }
}

async function downloadReport() {
    const campaignId = document.getElementById('logsCampaignSelect').value;
    if (!campaignId) {
        alert('Please select a campaign first');
        return;
    }
    
    window.location.href = `/api/campaigns/${campaignId}/report`;
}

async function updateStats() {
    try {
        const [hostsResponse, campaignsResponse] = await Promise.all([
            fetch('/api/hosts'),
            fetch('/api/campaigns')
        ]);
        
        const hosts = await hostsResponse.json();
        const campaigns = await campaignsResponse.json();
        
        document.getElementById('totalHosts').textContent = hosts.length;
        document.getElementById('totalCampaigns').textContent = campaigns.length;
    } catch (error) {
        console.error('Error updating stats:', error);
    }
}

function getCriticalityLabel(level) {
    const labels = {
        1: 'Low',
        2: 'Medium',
        3: 'High',
        4: 'Critical'
    };
    return labels[level] || 'Unknown';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

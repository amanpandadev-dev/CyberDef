import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
    Target,
    Shield,
    Info,
    ExternalLink,
    ChevronRight,
    Search
} from 'lucide-react';
import { getIncidents } from '../api';

// MITRE ATT&CK Tactic Descriptions
const TACTICS_INFO: Record<string, { description: string; color: string; examples: string[] }> = {
    'Initial Access': {
        description: 'Techniques that use various entry vectors to gain their initial foothold within a network.',
        color: '#ef4444',
        examples: ['Phishing', 'Drive-by Compromise', 'Valid Accounts']
    },
    'Execution': {
        description: 'Techniques that result in adversary-controlled code running on a local or remote system.',
        color: '#f97316',
        examples: ['Command Line Interface', 'PowerShell', 'Scripting']
    },
    'Persistence': {
        description: 'Techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions.',
        color: '#eab308',
        examples: ['Registry Run Keys', 'Scheduled Task', 'Boot or Logon Scripts']
    },
    'Privilege Escalation': {
        description: 'Techniques that adversaries use to gain higher-level permissions on a system or network.',
        color: '#84cc16',
        examples: ['Sudo Exploitation', 'Access Token Manipulation', 'Bypass UAC']
    },
    'Defense Evasion': {
        description: 'Techniques that adversaries use to avoid detection throughout their compromise.',
        color: '#22c55e',
        examples: ['Obfuscation', 'Disable Security Tools', 'Masquerading']
    },
    'Credential Access': {
        description: 'Techniques for stealing credentials like account names and passwords.',
        color: '#14b8a6',
        examples: ['Brute Force', 'Credential Dumping', 'Keylogging']
    },
    'Discovery': {
        description: 'Techniques that allow the adversary to gain knowledge about the system and internal network.',
        color: '#06b6d4',
        examples: ['Network Scanning', 'System Information Discovery', 'Account Discovery']
    },
    'Lateral Movement': {
        description: 'Techniques that adversaries use to enter and control remote systems on a network.',
        color: '#3b82f6',
        examples: ['Remote Services', 'Internal Spearphishing', 'Pass the Hash']
    },
    'Collection': {
        description: 'Techniques used to gather information relevant to the adversary\'s goals.',
        color: '#6366f1',
        examples: ['Data from Local System', 'Screen Capture', 'Email Collection']
    },
    'Command and Control': {
        description: 'Techniques that adversaries use to communicate with systems under their control.',
        color: '#8b5cf6',
        examples: ['Web Protocols', 'DNS', 'Encrypted Channel']
    },
    'Exfiltration': {
        description: 'Techniques that adversaries use to steal data from your network.',
        color: '#a855f7',
        examples: ['Exfiltration Over C2', 'Automated Exfiltration', 'Data Compressed']
    },
    'Impact': {
        description: 'Techniques that adversaries use to disrupt availability or compromise integrity.',
        color: '#ec4899',
        examples: ['Data Destruction', 'Defacement', 'Disk Wipe']
    }
};

export default function MitreMapping() {
    const [incidents, setIncidents] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');
    const [selectedTactic, setSelectedTactic] = useState<string | null>(null);

    useEffect(() => {
        const fetchIncidents = async () => {
            try {
                const data = await getIncidents();
                setIncidents(data);
            } catch (error) {
                console.error('Failed to fetch incidents:', error);
            } finally {
                setLoading(false);
            }
        };
        fetchIncidents();
    }, []);

    // Group incidents by tactic
    const incidentsByTactic = incidents.reduce((acc: Record<string, any[]>, incident) => {
        const tactic = incident.primary_tactic || 'Unknown';
        if (!acc[tactic]) acc[tactic] = [];
        acc[tactic].push(incident);
        return acc;
    }, {});

    // Get all tactics with counts
    const tacticsWithCounts = Object.entries(incidentsByTactic)
        .map(([tactic, items]) => ({
            tactic,
            count: items.length,
            info: TACTICS_INFO[tactic] || {
                description: 'Unclassified tactic',
                color: '#6b7280',
                examples: []
            }
        }))
        .sort((a, b) => b.count - a.count);

    // Filter tactics by search
    const filteredTactics = tacticsWithCounts.filter(t =>
        t.tactic.toLowerCase().includes(searchTerm.toLowerCase())
    );

    // Get incidents for selected tactic
    const selectedIncidents = selectedTactic ? incidentsByTactic[selectedTactic] || [] : [];

    return (
        <div className="space-y-8">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-xl font-bold flex items-center gap-3">
                        <Target className="w-8 h-8 text-purple-400" />
                        MITRE ATT&CK Mapping
                    </h1>
                    <p className="text-gray-400 mt-1">
                        Threat intelligence mapped to the MITRE ATT&CK framework
                    </p>
                </div>
                <a
                    href="https://attack.mitre.org/"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 text-sm text-primary-400 hover:text-primary-300"
                >
                    <ExternalLink className="w-4 h-4" />
                    MITRE ATT&CK Website
                </a>
            </div>

            {/* Info Card */}
            <div className="card bg-purple-500/10 border-purple-500/30">
                <div className="card-body">
                    <div className="flex items-start gap-4">
                        <div className="w-12 h-12 bg-purple-500/20 rounded-xl flex items-center justify-center flex-shrink-0">
                            <Info className="w-6 h-6 text-purple-400" />
                        </div>
                        <div>
                            <h3 className="font-semibold text-purple-300">About MITRE ATT&CK</h3>
                            <p className="text-gray-400 mt-1">
                                MITRE ATT&CK® is a globally accessible knowledge base of adversary tactics
                                and techniques based on real-world observations. AegisNet automatically maps
                                detected threats to ATT&CK tactics, helping security teams understand attacker
                                behavior and improve defenses.
                            </p>
                        </div>
                    </div>
                </div>
            </div>

            {/* Main Content */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Tactics List */}
                <div className="lg:col-span-1 card flex flex-col max-h-[600px]">
                    <div className="p-4 border-b border-white/10">
                        <h2 className="text-xl font-bold mb-4">Detected Tactics</h2>
                        <div className="relative">
                            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-500" />
                            <input
                                type="text"
                                placeholder="Search tactics..."
                                className="input pl-10"
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                            />
                        </div>
                    </div>

                    <div className="flex-1 overflow-y-auto p-2">
                        {loading ? (
                            <div className="text-center p-8 text-gray-500">Loading...</div>
                        ) : filteredTactics.length === 0 ? (
                            <div className="text-center p-8 text-gray-500">
                                <Target className="w-12 h-12 mx-auto mb-4 opacity-20" />
                                <p>No tactics detected</p>
                                <p className="text-sm mt-1">Run analysis to detect threats</p>
                            </div>
                        ) : (
                            <div className="space-y-2">
                                {filteredTactics.map(({ tactic, count, info }) => (
                                    <button
                                        key={tactic}
                                        onClick={() => setSelectedTactic(tactic)}
                                        className={`w-full text-left p-4 rounded-lg transition-all border ${selectedTactic === tactic
                                            ? 'bg-purple-500/20 border-purple-500/50'
                                            : 'bg-surface-dark border-transparent hover:bg-white/5'
                                            }`}
                                    >
                                        <div className="flex items-center justify-between">
                                            <div className="flex items-center gap-3">
                                                <div
                                                    className="w-3 h-3 rounded-full"
                                                    style={{ backgroundColor: info.color }}
                                                />
                                                <span className="text-base font-medium" style={{ fontFamily: "'Titillium Web', sans-serif", textTransform: 'none' }}>{tactic}</span>
                                            </div>
                                            <div className="flex items-center gap-2">
                                                <span className="text-sm bg-white/10 px-2 py-0.5 rounded">
                                                    {count}
                                                </span>
                                                <ChevronRight className="w-4 h-4 text-gray-500" />
                                            </div>
                                        </div>
                                    </button>
                                ))}
                            </div>
                        )}
                    </div>
                </div>

                {/* Tactic Details */}
                <div className="lg:col-span-2 space-y-6">
                    {selectedTactic ? (
                        <>
                            {/* Tactic Info */}
                            <div className="card">
                                <div className="card-header flex items-center gap-3">
                                    <div
                                        className="w-4 h-4 rounded-full"
                                        style={{ backgroundColor: TACTICS_INFO[selectedTactic]?.color || '#6b7280' }}
                                    />
                                    <h3 className="font-semibold text-lg">{selectedTactic}</h3>
                                </div>
                                <div className="card-body">
                                    <p className="text-gray-300 mb-4">
                                        {TACTICS_INFO[selectedTactic]?.description || 'No description available'}
                                    </p>

                                    {TACTICS_INFO[selectedTactic]?.examples.length > 0 && (
                                        <div>
                                            <h4 className="text-sm font-medium text-gray-400 mb-2">Common Techniques:</h4>
                                            <div className="flex flex-wrap gap-2">
                                                {TACTICS_INFO[selectedTactic].examples.map((ex) => (
                                                    <span
                                                        key={ex}
                                                        className="px-3 py-1 bg-white/5 rounded-full text-sm text-gray-300"
                                                    >
                                                        {ex}
                                                    </span>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            </div>

                            {/* Related Incidents */}
                            <div className="card">
                                <div className="card-header">
                                    <h3 className="font-semibold">
                                        Related Incidents ({selectedIncidents.length})
                                    </h3>
                                </div>
                                <div className="divide-y divide-white/10 max-h-[400px] overflow-y-auto">
                                    {selectedIncidents.map((incident) => (
                                        <Link
                                            key={incident.incident_id}
                                            to={`/incidents/${incident.incident_id}`}
                                            className="block p-4 hover:bg-white/5 transition-colors"
                                        >
                                            <div className="flex items-start justify-between">
                                                <div>
                                                    <h4 className="text-base font-medium" style={{ fontFamily: "'Titillium Web', sans-serif", textTransform: 'none' }}>{incident.title}</h4>
                                                    <p className="text-sm text-gray-400 mt-1 line-clamp-2">
                                                        {incident.description}
                                                    </p>
                                                </div>
                                                <span className={`px-2 py-1 rounded text-xs font-medium ${incident.priority === 'critical' ? 'bg-red-500/20 text-red-400' :
                                                    incident.priority === 'high' ? 'bg-orange-500/20 text-orange-400' :
                                                        incident.priority === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                                                            'bg-green-500/20 text-green-400'
                                                    }`}>
                                                    {incident.priority}
                                                </span>
                                            </div>
                                            <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                                                <span>ID: {incident.incident_id.slice(0, 8)}</span>
                                                <span>•</span>
                                                <span>{new Date(incident.first_seen).toLocaleDateString()}</span>
                                            </div>
                                        </Link>
                                    ))}
                                </div>
                            </div>
                        </>
                    ) : (
                        <div className="card h-full flex items-center justify-center">
                            <div className="text-center text-gray-500 p-12">
                                <Shield className="w-16 h-16 mx-auto mb-4 opacity-20" />
                                <p className="text-lg">Select a tactic to view details</p>
                                <p className="text-sm mt-2">
                                    Click on any tactic from the list to see related incidents and explanations
                                </p>
                            </div>
                        </div>
                    )}
                </div>
            </div>

            {/* Kill Chain Overview */}
            <div className="card">
                <div className="card-header">
                    <h3 className="font-semibold">Attack Kill Chain Overview</h3>
                </div>
                <div className="card-body">
                    <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
                        {Object.entries(TACTICS_INFO).slice(0, 12).map(([tactic, info]) => {
                            const count = incidentsByTactic[tactic]?.length || 0;
                            return (
                                <button
                                    key={tactic}
                                    onClick={() => setSelectedTactic(tactic)}
                                    className={`p-4 rounded-lg text-center transition-all border ${count > 0
                                        ? 'bg-surface-dark border-white/10 hover:border-white/30'
                                        : 'bg-surface-light/50 border-transparent opacity-50'
                                        }`}
                                >
                                    <div
                                        className="w-8 h-8 rounded-full mx-auto mb-2 flex items-center justify-center"
                                        style={{ backgroundColor: `${info.color}30` }}
                                    >
                                        <div
                                            className="w-3 h-3 rounded-full"
                                            style={{ backgroundColor: info.color }}
                                        />
                                    </div>
                                    <p className="text-xs font-medium truncate" style={{ fontFamily: "'Titillium Web', sans-serif", textTransform: 'none' }}>{tactic}</p>
                                    <p className="text-lg font-bold mt-1" style={{ color: count > 0 ? info.color : '#6b7280' }}>
                                        {count}
                                    </p>
                                </button>
                            );
                        })}
                    </div>
                </div>
            </div>
        </div>
    );
}

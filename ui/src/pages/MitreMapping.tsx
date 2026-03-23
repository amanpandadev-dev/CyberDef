import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
    Target,
    Shield,
    Info,
    ExternalLink,
    ChevronRight,
    Search,
} from 'lucide-react';
import { getIncidents } from '../api';
import { formatISTDateTime } from '../utils/datetime';

interface IncidentMitre {
    incident_id: string;
    title: string;
    description?: string;
    priority: string;
    first_seen: string;
    primary_tactic?: string | null;
    mitre_tactic?: string | null;
    mitre_technique?: string | null;
    attack_name?: string | null;
}

const TACTICS_INFO: Record<string, { description: string; color: string; examples: string[] }> = {
    'Initial Access': {
        description: 'Techniques used to gain initial foothold in a network.',
        color: '#ef4444',
        examples: ['Phishing', 'Drive-by Compromise', 'Valid Accounts'],
    },
    Execution: {
        description: 'Techniques that result in adversary-controlled code execution.',
        color: '#f97316',
        examples: ['Command Line Interface', 'PowerShell', 'Scripting'],
    },
    Persistence: {
        description: 'Techniques to maintain access across interruptions and restarts.',
        color: '#eab308',
        examples: ['Registry Run Keys', 'Scheduled Tasks', 'Startup Items'],
    },
    Discovery: {
        description: 'Techniques that help attackers learn internal system context.',
        color: '#06b6d4',
        examples: ['Network Scanning', 'System Discovery', 'Account Discovery'],
    },
    'Credential Access': {
        description: 'Techniques focused on stealing account credentials.',
        color: '#14b8a6',
        examples: ['Brute Force', 'Credential Dumping', 'Keylogging'],
    },
    'Command and Control': {
        description: 'Techniques for attacker communication with compromised systems.',
        color: '#8b5cf6',
        examples: ['Web Protocols', 'DNS', 'Encrypted Channel'],
    },
    Exfiltration: {
        description: 'Techniques used to transfer stolen data out of a network.',
        color: '#a855f7',
        examples: ['Automated Exfiltration', 'Exfiltration Over C2', 'Archive Collected Data'],
    },
    Impact: {
        description: 'Techniques to disrupt or destroy system availability and integrity.',
        color: '#ec4899',
        examples: ['Data Destruction', 'Defacement', 'Disk Wipe'],
    },
};

export default function MitreMapping() {
    const [incidents, setIncidents] = useState<IncidentMitre[]>([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');
    const [selectedTactic, setSelectedTactic] = useState<string | null>(null);

    useEffect(() => {
        const fetchIncidents = async () => {
            try {
                const data = await getIncidents();
                setIncidents(data || []);
            } catch (error) {
                console.error('Failed to fetch incidents:', error);
            } finally {
                setLoading(false);
            }
        };
        fetchIncidents();
    }, []);

    const incidentsByTactic = useMemo(() => {
        return incidents.reduce((acc: Record<string, IncidentMitre[]>, incident) => {
            const tactic = incident.mitre_tactic || incident.primary_tactic || 'Unknown';
            if (!acc[tactic]) acc[tactic] = [];
            acc[tactic].push(incident);
            return acc;
        }, {});
    }, [incidents]);

    const tacticsWithCounts = useMemo(
        () =>
            Object.entries(incidentsByTactic)
                .map(([tactic, items]) => ({
                    tactic,
                    count: items.length,
                    info: TACTICS_INFO[tactic] || {
                        description: 'Unclassified tactic',
                        color: '#64748b',
                        examples: [],
                    },
                }))
                .sort((a, b) => b.count - a.count),
        [incidentsByTactic],
    );

    const filteredTactics = useMemo(
        () =>
            tacticsWithCounts.filter((item) =>
                item.tactic.toLowerCase().includes(searchTerm.toLowerCase()),
            ),
        [tacticsWithCounts, searchTerm],
    );

    const selectedIncidents = selectedTactic ? incidentsByTactic[selectedTactic] || [] : [];

    return (
        <div className="space-y-8">
            <div className="flex items-center justify-between gap-4">
                <div>
                    <h1 className="text-xl font-bold flex items-center gap-3">
                        <Target className="w-8 h-8 text-primary-600" />
                        MITRE ATT&CK Mapping
                    </h1>
                    <p className="mt-1 text-slate-600">
                        Per-incident MITRE tactics and techniques mapped from analysis results
                    </p>
                </div>
                <a
                    href="https://attack.mitre.org/"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 text-sm text-primary-600 hover:text-primary-700"
                >
                    <ExternalLink className="w-4 h-4" />
                    MITRE ATT&CK Website
                </a>
            </div>

            <div className="card border-primary-200 bg-primary-50/60">
                <div className="card-body">
                    <div className="flex items-start gap-4">
                        <div className="w-11 h-11 rounded-xl bg-white border border-primary-200 text-primary-600 flex items-center justify-center">
                            <Info className="w-5 h-5" />
                        </div>
                        <div>
                            <h3 className="font-semibold text-primary-700">MITRE Context</h3>
                            <p className="mt-1 text-sm text-slate-600">
                                Every incident should include mapped tactic and technique data for triage, reporting, and threat hunting workflows.
                            </p>
                        </div>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="card flex flex-col max-h-[640px]">
                    <div className="p-4 border-b border-slate-200">
                        <h2 className="text-lg font-semibold mb-3">Detected Tactics</h2>
                        <div className="relative">
                            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                            <input
                                type="text"
                                placeholder="Search tactics..."
                                className="input pl-10"
                                value={searchTerm}
                                onChange={(event) => setSearchTerm(event.target.value)}
                            />
                        </div>
                    </div>

                    <div className="flex-1 overflow-y-auto p-2">
                        {loading ? (
                            <div className="text-center p-8 text-slate-500">Loading...</div>
                        ) : filteredTactics.length === 0 ? (
                            <div className="text-center p-8 text-slate-500">
                                <Target className="w-12 h-12 mx-auto mb-3 opacity-25" />
                                <p>No tactics found</p>
                            </div>
                        ) : (
                            <div className="space-y-2">
                                {filteredTactics.map(({ tactic, count, info }) => (
                                    <button
                                        key={tactic}
                                        onClick={() => setSelectedTactic(tactic)}
                                        className={`w-full text-left p-3 rounded-lg transition-all border ${
                                            selectedTactic === tactic
                                                ? 'bg-primary-50 border-primary-300'
                                                : 'bg-white border-slate-200 hover:bg-slate-50'
                                        }`}
                                    >
                                        <div className="flex items-center justify-between">
                                            <div className="flex items-center gap-3">
                                                <span className="w-3 h-3 rounded-full" style={{ backgroundColor: info.color }} />
                                                <span className="font-medium text-slate-800">{tactic}</span>
                                            </div>
                                            <div className="flex items-center gap-2">
                                                <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-700">
                                                    {count}
                                                </span>
                                                <ChevronRight className="w-4 h-4 text-slate-400" />
                                            </div>
                                        </div>
                                    </button>
                                ))}
                            </div>
                        )}
                    </div>
                </div>

                <div className="lg:col-span-2 space-y-6">
                    {selectedTactic ? (
                        <>
                            <div className="card">
                                <div className="card-header flex items-center gap-3">
                                    <span
                                        className="w-4 h-4 rounded-full"
                                        style={{
                                            backgroundColor:
                                                TACTICS_INFO[selectedTactic]?.color || '#64748b',
                                        }}
                                    />
                                    <h3 className="font-semibold text-lg">{selectedTactic}</h3>
                                </div>
                                <div className="card-body">
                                    <p className="text-slate-700">
                                        {TACTICS_INFO[selectedTactic]?.description || 'No description available'}
                                    </p>
                                    {TACTICS_INFO[selectedTactic]?.examples.length ? (
                                        <div className="mt-4">
                                            <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500 mb-2">
                                                Common Examples
                                            </p>
                                            <div className="flex flex-wrap gap-2">
                                                {TACTICS_INFO[selectedTactic].examples.map((example) => (
                                                    <span
                                                        key={example}
                                                        className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs text-slate-700"
                                                    >
                                                        {example}
                                                    </span>
                                                ))}
                                            </div>
                                        </div>
                                    ) : null}
                                </div>
                            </div>

                            <div className="card">
                                <div className="card-header">
                                    <h3 className="font-semibold">
                                        Related Incidents ({selectedIncidents.length})
                                    </h3>
                                </div>
                                <div className="divide-y divide-slate-200 max-h-[420px] overflow-y-auto">
                                    {selectedIncidents.map((incident) => (
                                        <Link
                                            key={incident.incident_id}
                                            to={`/incidents/${incident.incident_id}`}
                                            className="block p-4 hover:bg-slate-50 transition-colors"
                                        >
                                            <div className="flex items-start justify-between gap-4">
                                                <div>
                                                    <h4 className="font-medium text-slate-900">
                                                        {incident.attack_name || incident.title}
                                                    </h4>
                                                    <p className="mt-1 text-sm text-slate-600">
                                                        Technique: {incident.mitre_technique || 'N/A'}
                                                    </p>
                                                </div>
                                                <span className="rounded-full bg-slate-100 px-2 py-1 text-xs font-semibold text-slate-700">
                                                    {incident.priority}
                                                </span>
                                            </div>
                                            <p className="mt-2 text-xs text-slate-500">
                                                {formatISTDateTime(incident.first_seen)}
                                            </p>
                                        </Link>
                                    ))}
                                </div>
                            </div>
                        </>
                    ) : (
                        <div className="card h-full flex items-center justify-center">
                            <div className="text-center text-slate-500 p-12">
                                <Shield className="w-16 h-16 mx-auto mb-4 opacity-20" />
                                <p className="text-lg">Select a tactic to view details</p>
                                <p className="text-sm mt-2">
                                    Choose a tactic from the list to inspect mapped incidents and techniques.
                                </p>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}

import { useEffect, useMemo, useState } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';
import logoSrc from './logo-vanquish.png';

const apiBase = import.meta.env.VITE_API_BASE || '/api';

// ── CVSS 3.1 environmental score helpers (module scope) ──────────────────────
const CVSS_AV  = { N:0.85, A:0.62, L:0.55, P:0.20 };
const CVSS_AC  = { L:0.77, H:0.44 };
const CVSS_PR_U = { N:0.85, L:0.62, H:0.27 };
const CVSS_PR_C = { N:0.85, L:0.50, H:0.50 };
const CVSS_UI  = { N:0.85, R:0.62 };
const CVSS_IMP = { N:0.00, L:0.22, H:0.56 };
const CVSS_REQ = { X:1.00, L:0.50, M:1.00, H:1.50 };

const CVSS_ENV_METRICS = [
  { group: 'Modified Base Metrics', items: [
    { key:'MAV', label:'Modified Attack Vector',       opts:[['X','Not Defined'],['N','Network (0.85)'],['A','Adjacent (0.62)'],['L','Local (0.55)'],['P','Physical (0.20)']] },
    { key:'MAC', label:'Modified Attack Complexity',   opts:[['X','Not Defined'],['L','Low (0.77)'],['H','High (0.44)']] },
    { key:'MPR', label:'Modified Privileges Required', opts:[['X','Not Defined'],['N','None (0.85)'],['L','Low'],['H','High']] },
    { key:'MUI', label:'Modified User Interaction',    opts:[['X','Not Defined'],['N','None (0.85)'],['R','Required (0.62)']] },
    { key:'MS',  label:'Modified Scope',               opts:[['X','Not Defined'],['U','Unchanged'],['C','Changed']] },
    { key:'MC',  label:'Modified Confidentiality',     opts:[['X','Not Defined'],['N','None (0.00)'],['L','Low (0.22)'],['H','High (0.56)']] },
    { key:'MI',  label:'Modified Integrity',           opts:[['X','Not Defined'],['N','None (0.00)'],['L','Low (0.22)'],['H','High (0.56)']] },
    { key:'MA',  label:'Modified Availability',        opts:[['X','Not Defined'],['N','None (0.00)'],['L','Low (0.22)'],['H','High (0.56)']] },
  ]},
  { group: 'Environmental Requirements', items: [
    { key:'CR', label:'Confidentiality Requirement', opts:[['X','Not Defined (1.00)'],['L','Low (0.50)'],['M','Medium (1.00)'],['H','High (1.50)']] },
    { key:'IR', label:'Integrity Requirement',       opts:[['X','Not Defined (1.00)'],['L','Low (0.50)'],['M','Medium (1.00)'],['H','High (1.50)']] },
    { key:'AR', label:'Availability Requirement',    opts:[['X','Not Defined (1.00)'],['L','Low (0.50)'],['M','Medium (1.00)'],['H','High (1.50)']] },
  ]},
];

const cvssRoundup = (x) => {
  const i = Math.round(x * 100000);
  return (i % 10000 === 0) ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
};

const parseCvssVector = (v) => {
  if (!v) return null;
  const str = v.replace(/^CVSS:[0-9.]+\//, '');
  return Object.fromEntries(str.split('/').map(s => s.split(':')));
};

const calcEnvScore = (vectorStr, env) => {
  const base = parseCvssVector(vectorStr);
  if (!base) return null;
  const mav = env.MAV !== 'X' ? CVSS_AV[env.MAV]  : CVSS_AV[base.AV];
  const mac = env.MAC !== 'X' ? CVSS_AC[env.MAC]  : CVSS_AC[base.AC];
  const mui = env.MUI !== 'X' ? CVSS_UI[env.MUI]  : CVSS_UI[base.UI];
  const ms  = env.MS  !== 'X' ? env.MS             : base.S;
  const prTable = ms === 'C' ? CVSS_PR_C : CVSS_PR_U;
  const mpr = env.MPR !== 'X' ? prTable[env.MPR]   : prTable[base.PR];
  const mc  = env.MC  !== 'X' ? CVSS_IMP[env.MC]  : CVSS_IMP[base.C];
  const mi  = env.MI  !== 'X' ? CVSS_IMP[env.MI]  : CVSS_IMP[base.I];
  const ma  = env.MA  !== 'X' ? CVSS_IMP[env.MA]  : CVSS_IMP[base.A];
  if ([mav,mac,mui,mpr,mc,mi,ma].some(v => v === undefined)) return null;
  const cr = CVSS_REQ[env.CR]; const ir = CVSS_REQ[env.IR]; const ar = CVSS_REQ[env.AR];
  const modISC = Math.min(1 - (1-mc*cr)*(1-mi*ir)*(1-ma*ar), 0.915);
  const modISCScoped = ms === 'U'
    ? 6.42 * modISC
    : 7.52*(modISC-0.029) - 3.25*Math.pow(modISC-0.02, 15);
  if (modISCScoped <= 0) return 0.0;
  const modExp = 8.22 * mav * mac * mpr * mui;
  const raw = ms === 'U'
    ? cvssRoundup(Math.min(modISCScoped + modExp, 10))
    : cvssRoundup(Math.min(1.08*(modISCScoped + modExp), 10));
  return cvssRoundup(raw);
};

const getCvssScoreLabel = (score) => {
  if (score === null || score === undefined) return '';
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  if (score > 0)   return 'Low';
  return 'None';
};

const getCvssScoreClass = (score) => {
  if (score === null || score === undefined) return 'none';
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score > 0)   return 'low';
  return 'none';
};

const getSeverityBadgeClass = (severity) => {
  switch (String(severity).toLowerCase()) {
    case 'critical': return 'severity-badge-critical';
    case 'high':     return 'severity-badge-high';
    case 'medium':   return 'severity-badge-medium';
    case 'low':      return 'severity-badge-low';
    default:         return 'severity-badge-unknown';
  }
};

function App() {
  const [findings, setFindings] = useState([]);
  const [message, setMessage] = useState('');
  const [isDark, setIsDark] = useState(false);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [loginUsername, setLoginUsername] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [currentTab, setCurrentTab] = useState('main');
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [file, setFile] = useState(null);
  const [filters, setFilters] = useState({});
  const [exceptionType, setExceptionType] = useState('');
  const [exceptionJustification, setExceptionJustification] = useState('');
  const [showCvssCalc, setShowCvssCalc] = useState(false);
  const [cvssEnv, setCvssEnv] = useState({
    MAV:'X', MAC:'X', MPR:'X', MUI:'X', MS:'X',
    MC:'X', MI:'X', MA:'X', CR:'X', IR:'X', AR:'X'
  });
  const [pageSize, setPageSize] = useState(50);
  const [currentPage, setCurrentPage] = useState(1);

  const handleFilter = (column, value) => {
    setCurrentPage(1);
    setFilters(prev => ({ ...prev, [column]: value }));
  };

  const clearFilter = (column) => {
    setCurrentPage(1);
    const newFilters = { ...filters };
    delete newFilters[column];
    setFilters(newFilters);
  };

  const filteredFindings = useMemo(() => {
    return findings.filter((finding) => {
      const fieldMap = {
        id: String(finding.id ?? ''),
        asset: String(finding.ocsf?.asset?.name ?? finding.asset_name ?? ''),
        severity: String(finding.ocsf?.vulnerability?.severity ?? finding.severity ?? ''),
        title: String(finding.ocsf?.vulnerability?.title ?? ''),
        detector_id: String(finding.ocsf?.vulnerability?.detector_id ?? ''),
        source: String(finding.source ?? ''),
        detected: String(finding.created_at ? new Date(finding.created_at).toLocaleString() : ''),
      };
      return Object.entries(filters).every(([key, value]) => {
        if (!value) return true;
        return fieldMap[key]?.toLowerCase().includes(String(value).toLowerCase());
      });
    });
  }, [findings, filters]);

  const totalPages = Math.max(1, Math.ceil(filteredFindings.length / pageSize));

  const pagedFindings = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredFindings.slice(start, start + pageSize);
  }, [filteredFindings, currentPage, pageSize]);

  const severityCounts = useMemo(() => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Unknown: 0 };
    findings.forEach((finding) => {
      const severity = String(finding.ocsf?.vulnerability?.severity || '').toLowerCase();
      if (severity === 'critical') counts.Critical++;
      else if (severity === 'high') counts.High++;
      else if (severity === 'medium') counts.Medium++;
      else if (severity === 'low') counts.Low++;
      else counts.Unknown++;
    });
    return [
      { name: 'Critical', value: counts.Critical, color: '#dc2626' },
      { name: 'High', value: counts.High, color: '#ef4444' },
      { name: 'Medium', value: counts.Medium, color: '#f59e0b' },
      { name: 'Low', value: counts.Low, color: '#3b82f6' },
      { name: 'Unknown', value: counts.Unknown, color: '#6b7280' }
    ];
  }, [findings]);

  useEffect(() => {
    const savedTheme = localStorage.getItem('theme');
    const darkMode = savedTheme === 'dark';
    setIsDark(darkMode);
    document.body.classList.toggle('dark', darkMode);
  }, []);

  const toggleTheme = () => {
    const newIsDark = !isDark;
    setIsDark(newIsDark);
    document.body.classList.toggle('dark', newIsDark);
    localStorage.setItem('theme', newIsDark ? 'dark' : 'light');
  };

  const handleLogin = async (event) => {
    event.preventDefault();
    const response = await fetch(`${apiBase}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: loginUsername, password: loginPassword }),
    });
    const data = await response.json();
    if (data.success) {
      setIsLoggedIn(true);
      fetchFindings();
    } else {
      setMessage('Login failed: ' + data.error);
    }
  };

  const handleLogout = () => {
    setIsLoggedIn(false);
    setLoginUsername('');
    setLoginPassword('');
    setMessage('');
  };

  useEffect(() => {
    if (isLoggedIn) {
      fetchFindings();
    }
  }, [isLoggedIn]);

  const fetchFindings = async () => {
    const response = await fetch(`${apiBase}/vulnerabilities`);
    const data = await response.json();
    setFindings(data.findings || []);
  };

  const handleKevIngest = async (event) => {
    event.preventDefault();
    try {
      const response = await fetch(`${apiBase}/ingest/kev`, {
        method: 'POST',
      });

      const data = await response.json();
      if (response.ok) {
        setMessage(`Imported ${data.imported} KEV records.`);
      } else {
        setMessage(data.error || 'KEV import failed.');
      }
    } catch (error) {
      setMessage('Error downloading or uploading KEV file: ' + error.message);
    }
  };

  const handleCsvUpload = async (csvFile) => {
    const formData = new FormData();
    formData.append('file', csvFile);

    const response = await fetch(`${apiBase}/upload/csv`, {
      method: 'POST',
      body: formData,
    });

    const data = await response.json();
    if (response.ok) {
      setMessage(`Imported ${data.imported} records from CSV.`);
      fetchFindings();
    } else {
      setMessage(data.error || 'Upload failed.');
    }
  };

  const handlePopulateCvss = async () => {
    const response = await fetch(`${apiBase}/populate/cvss`, {
      method: 'POST',
    });
    const data = await response.json();
    if (response.ok) {
      setMessage(`Populated CVSS for ${data.populated} CVEs.`);
    } else {
      setMessage(data.error || 'Populate CVSS failed.');
    }
  };

  const exportPoam = async () => {
    const response = await fetch(`${apiBase}/export/poam`);
    if (!response.ok) {
      setMessage('Failed to export POA&M.');
      return;
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'poam-report.csv';
    link.click();
    URL.revokeObjectURL(url);
    setMessage('POA&M exported successfully.');
  };

  const handleIngest = async (event) => {
    event.preventDefault();
    if (!file) {
      setMessage('Please select a file first.');
      return;
    }
    if (file.name.endsWith('.csv')) {
      await handleCsvUpload(file);
    } else if (file.name.endsWith('.json')) {
      await handleJsonUpload(file);
    } else if (file.name.endsWith('.xml')) {
      await handleXmlUpload(file);
    } else {
      setMessage('Unsupported file type.');
    }
  };

  const handleJsonUpload = async (jsonFile) => {
    const formData = new FormData();
    formData.append('file', jsonFile);

    const response = await fetch(`${apiBase}/upload/json`, {
      method: 'POST',
      body: formData,
    });

    const data = await response.json();
    if (response.ok) {
      setMessage(`Imported ${data.imported} records from JSON.`);
      fetchFindings();
    } else {
      setMessage(data.error || 'Upload failed.');
    }
  };

  const handleXmlUpload = async (xmlFile) => {
    const formData = new FormData();
    formData.append('file', xmlFile);

    const response = await fetch(`${apiBase}/upload/xml`, {
      method: 'POST',
      body: formData,
    });

    const data = await response.json();
    if (response.ok) {
      setMessage(`Imported ${data.imported} records from XML.`);
      fetchFindings();
    } else {
      setMessage(data.error || 'Upload failed.');
    }
  };

  // ── useMemo: adjusted environmental CVSS score ──────────────────────────────
  const adjustedCvssScore = useMemo(() => {
    if (!selectedFinding || !showCvssCalc) return null;
    const vector = selectedFinding.cvss_vector;
    if (!vector) return null;
    return calcEnvScore(vector, cvssEnv);
  }, [selectedFinding, showCvssCalc, cvssEnv]);

  // ── Reset exception state when a different finding is opened ────────────────
  useEffect(() => {
    if (selectedFinding) {
      setExceptionType('');
      setExceptionJustification('');
      setShowCvssCalc(false);
      setCvssEnv({ MAV:'X', MAC:'X', MPR:'X', MUI:'X', MS:'X', MC:'X', MI:'X', MA:'X', CR:'X', IR:'X', AR:'X' });
    }
  }, [selectedFinding?.id]);

  const handleSaveException = () => {
    if (!exceptionType || !exceptionJustification.trim()) {
      setMessage('Please select an exception type and provide a justification.');
      return;
    }
    const label = { false_positive:'False Positive', operational_requirement:'Operational Requirement', vendor_dependency:'Vendor Dependency', risk_adjustment:'Risk Adjustment' }[exceptionType];
    const adj = adjustedCvssScore !== null ? ` (adjusted CVSS: ${adjustedCvssScore})` : '';
    setMessage(`Risk exception "${label}"${adj} recorded for finding #${selectedFinding.id}.`);
    setExceptionType('');
    setExceptionJustification('');
    setShowCvssCalc(false);
  };

  // ── Helper sub-components ────────────────────────────────────────────────────
  const DetailField = ({ label, value, children }) => (
    <div className="detail-field">
      <div className="detail-field-label">{label}</div>
      <div className="detail-field-value">{children ?? value ?? '—'}</div>
    </div>
  );

  const VulnerabilityList = ({ items }) => (
    <div className="space-y-2">
      {items.length === 0 ? (
        <div className="text-sm text-gray-500 py-8 text-center">No vulnerabilities</div>
      ) : (
        items.map(finding => (
          <div key={finding.id} className="p-3 bg-white border border-gray-200 rounded hover:border-gray-300 transition-colors">
            <div className="flex items-start justify-between gap-3 mb-2">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-sm font-mono text-gray-500">{finding.id}</span>
                  <span className={`severity-badge ${getSeverityBadgeClass(finding.ocsf.vulnerability.severity)}`}>
                    {finding.ocsf.vulnerability.severity}
                  </span>
                </div>
                <div className="text-sm mb-1">{finding.ocsf.vulnerability.title}</div>
              </div>
              <div className="text-xs text-gray-500 whitespace-nowrap">
                {new Date(finding.created_at).toLocaleDateString()}
              </div>
            </div>
            <div className="text-xs text-gray-600">{finding.ocsf.asset.name}</div>
          </div>
        ))
      )}
    </div>
  );

  return (
    <div className="app-shell">
      {!isLoggedIn ? (
        <div className="login-container">
          <button className="theme-toggle" onClick={toggleTheme}>
            {isDark ? '☀️' : '🌙'}
          </button>
          <div className="login-header">
            <img className="logo" src={logoSrc} alt="Vanquish logo" />
            <div className="title-section">
              <h1>VANQUISH</h1>
              <h2><strong>V</strong>ulnerablity <strong>A</strong>ssessment & <strong>N</strong>on-compliance <strong>Q</strong>ueue - <strong>U</strong>nified <strong>I</strong>ssue <strong>S</strong>tatus <strong>H</strong>ub</h2>
              <p>POA&M <strong>•</strong> FedRAMP <strong>•</strong> Centralized</p>
            </div>
          </div>
          <form onSubmit={handleLogin} className="login-form">
            <input
              type="text"
              placeholder="Username"
              value={loginUsername}
              onChange={(e) => setLoginUsername(e.target.value)}
              required
            />
            <input
              type="password"
              placeholder="Password"
              value={loginPassword}
              onChange={(e) => setLoginPassword(e.target.value)}
              required
            />
            <button type="submit">Login</button>
          </form>
          {message && <div className="message">{message}</div>}
        </div>
      ) : (
        <>
          <header>
            <div className="header-content">
              <img className="logo" src={logoSrc} alt="Vanquish logo" />
              <div className="title-section">
              <h2>VANQUISH - <strong>U</strong>nified <strong>I</strong>ssue <strong>S</strong>tatus <strong>H</strong>ub</h2>
              </div>
            </div>
          </header>

          <nav className="tabs">
            <button className={currentTab === 'main' ? 'active' : ''} onClick={() => setCurrentTab('main')}>Vulnerabilities</button>
            <button className={currentTab === 'ingest' ? 'active' : ''} onClick={() => setCurrentTab('ingest')}>Ingest</button>
            <button type="button" onClick={fetchFindings}>Refresh Findings</button>
            <button type="button" onClick={exportPoam}>Export POA&M</button>
            <button className={currentTab === 'reports' ? 'active' : ''} onClick={() => setCurrentTab('reports')}>Reports</button>
            <button className={currentTab === 'admin' ? 'active' : ''} onClick={() => setCurrentTab('admin')}>Admin</button>
            <button onClick={handleLogout} className="logout-btn">Logout</button>
          </nav>

          {message && <div className="message">{message}</div>}

          {currentTab === 'main' && (
            <>
              <section className="panel">
                <div className="table-wrapper">
                  <table className="w-full">
                    <thead className="bg-gray-50 border-b border-gray-200">
                      <tr>
                        <th className="px-4 py-3 text-left">
                          <div className="space-y-2">
                            <div>ID</div>
                            <div className="relative">
                              <input
                                type="text"
                                placeholder="Filter..."
                                value={filters.id || ''}
                                onChange={(e) => handleFilter('id', e.target.value)}
                                className="w-full pl-2 pr-7 py-1 text-sm border border-gray-300 rounded"
                              />
                              {filters.id && (
                                <button
                                  onClick={() => clearFilter('id')}
                                  className="absolute right-2 top-1/2 -translate-y-1/2"
                                >
                                  ×
                                </button>
                              )}
                            </div>
                          </div>
                        </th>
                        <th className="px-4 py-3 text-left">
                          <div className="space-y-2">
                            <div>Asset</div>
                            <div className="relative">
                              <input
                                type="text"
                                placeholder="Filter..."
                                value={filters.asset || ''}
                                onChange={(e) => handleFilter('asset', e.target.value)}
                                className="w-full pl-2 pr-7 py-1 text-sm border border-gray-300 rounded"
                              />
                              {filters.asset && (
                                <button
                                  onClick={() => clearFilter('asset')}
                                  className="absolute right-2 top-1/2 -translate-y-1/2"
                                >
                                  ×
                                </button>
                              )}
                            </div>
                          </div>
                        </th>
                        <th className="px-4 py-3 text-left">
                          <div className="space-y-2">
                            <div>Severity</div>
                            <div className="relative">
                              <input
                                type="text"
                                placeholder="Filter..."
                                value={filters.severity || ''}
                                onChange={(e) => handleFilter('severity', e.target.value)}
                                className="w-full pl-2 pr-7 py-1 text-sm border border-gray-300 rounded"
                              />
                              {filters.severity && (
                                <button
                                  onClick={() => clearFilter('severity')}
                                  className="absolute right-2 top-1/2 -translate-y-1/2"
                                >
                                  ×
                                </button>
                              )}
                            </div>
                          </div>
                        </th>
                        <th className="px-4 py-3 text-left">
                          <div className="space-y-2">
                            <div>Vulnerability</div>
                            <div className="relative">
                              <input
                                type="text"
                                placeholder="Filter..."
                                value={filters.title || ''}
                                onChange={(e) => handleFilter('title', e.target.value)}
                                className="w-full pl-2 pr-7 py-1 text-sm border border-gray-300 rounded"
                              />
                              {filters.title && (
                                <button
                                  onClick={() => clearFilter('title')}
                                  className="absolute right-2 top-1/2 -translate-y-1/2"
                                >
                                  ×
                                </button>
                              )}
                            </div>
                          </div>
                        </th>
                        <th className="px-4 py-3 text-left">
                          <div className="space-y-2">
                            <div>Vulnerability ID</div>
                            <div className="relative">
                              <input
                                type="text"
                                placeholder="Filter..."
                                value={filters.detector_id || ''}
                                onChange={(e) => handleFilter('detector_id', e.target.value)}
                                className="w-full pl-2 pr-7 py-1 text-sm border border-gray-300 rounded"
                              />
                              {filters.detector_id && (
                                <button
                                  onClick={() => clearFilter('detector_id')}
                                  className="absolute right-2 top-1/2 -translate-y-1/2"
                                >
                                  ×
                                </button>
                              )}
                            </div>
                          </div>
                        </th>
                        <th className="px-4 py-3 text-left">
                          <div className="space-y-2">
                            <div>Source</div>
                            <div className="relative">
                              <input
                                type="text"
                                placeholder="Filter..."
                                value={filters.source || ''}
                                onChange={(e) => handleFilter('source', e.target.value)}
                                className="w-full pl-2 pr-7 py-1 text-sm border border-gray-300 rounded"
                              />
                              {filters.source && (
                                <button
                                  onClick={() => clearFilter('source')}
                                  className="absolute right-2 top-1/2 -translate-y-1/2"
                                >
                                  ×
                                </button>
                              )}
                            </div>
                          </div>
                        </th>
                        <th className="px-4 py-3 text-left">
                          <div className="space-y-2">
                            <div>Detected</div>
                            <div className="relative">
                              <input
                                type="text"
                                placeholder="Filter..."
                                value={filters.detected || ''}
                                onChange={(e) => handleFilter('detected', e.target.value)}
                                className="w-full pl-2 pr-7 py-1 text-sm border border-gray-300 rounded"
                                style={{ minWidth: '120px' }}
                              />
                              {filters.detected && (
                                <button
                                  onClick={() => clearFilter('detected')}
                                  className="absolute right-2 top-1/2 -translate-y-1/2"
                                >
                                  ×
                                </button>
                              )}
                            </div>
                          </div>
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {pagedFindings.length === 0 && (
                        <tr>
                          <td colSpan="7">No findings stored yet.</td>
                        </tr>
                      )}
                      {pagedFindings.map((finding) => (
                        <tr key={finding.id} onClick={() => setSelectedFinding(finding)} style={{ cursor: 'pointer' }}>
                          <td className="px-4 py-3">{finding.id}</td>
                          <td className="px-4 py-3">{finding.ocsf.asset.name}</td>
                          <td className="px-4 py-3">
                            <span className={`severity-badge ${getSeverityBadgeClass(finding.ocsf.vulnerability.severity)}`}>
                              {finding.ocsf.vulnerability.severity}
                            </span>
                          </td>
                          <td className="px-4 py-3">{finding.ocsf.vulnerability.title}</td>
                          <td className="px-4 py-3">{finding.ocsf.vulnerability.detector_id || 'N/A'}</td>
                          <td className="px-4 py-3">{finding.source}</td>
                          <td className="px-4 py-3">{new Date(finding.created_at).toLocaleString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {/* ── Pagination bar ── */}
                <div className="pagination-bar">
                  <div className="pagination-info">
                    {filteredFindings.length === 0
                      ? 'No results'
                      : `${(currentPage - 1) * pageSize + 1}–${Math.min(currentPage * pageSize, filteredFindings.length)} of ${filteredFindings.length}`}
                  </div>
                  <div className="pagination-controls">
                    <button className="page-btn" onClick={() => setCurrentPage(1)} disabled={currentPage === 1} title="First page">«</button>
                    <button className="page-btn" onClick={() => setCurrentPage(p => p - 1)} disabled={currentPage === 1} title="Previous page">‹</button>
                    <span className="page-indicator">Page {currentPage} of {totalPages}</span>
                    <button className="page-btn" onClick={() => setCurrentPage(p => p + 1)} disabled={currentPage === totalPages} title="Next page">›</button>
                    <button className="page-btn" onClick={() => setCurrentPage(totalPages)} disabled={currentPage === totalPages} title="Last page">»</button>
                  </div>
                  <div className="pagination-size">
                    <label>Rows per page</label>
                    <select
                      value={pageSize}
                      onChange={e => { setPageSize(Number(e.target.value)); setCurrentPage(1); }}
                    >
                      {[25, 50, 100, 250].map(n => <option key={n} value={n}>{n}</option>)}
                    </select>
                  </div>
                </div>
              </section>

              {/* ── Detail modal ── */}
              {selectedFinding && (
                <div className="modal-overlay" onClick={e => { if (e.target === e.currentTarget) setSelectedFinding(null); }}>
                  <div className="modal-panel">
                    {/* Header */}
                    <div className="finding-detail-header">
                      <h2>Vulnerability Details</h2>
                      <button className="btn-close" onClick={() => setSelectedFinding(null)}>✕ Close</button>
                    </div>

                    {/* Two-column: info + exception */}
                    <div className="modal-body">
                      <div className="finding-detail-grid">
                        {/* Left: fields */}
                        <div className="finding-detail-info">
                          <DetailField label="CVE / Vuln ID"  value={selectedFinding.ocsf.vulnerability.detector_id || 'N/A'} />
                          <DetailField label="Title"          value={selectedFinding.ocsf.vulnerability.title || 'N/A'} />
                          <DetailField label="Description"    value={selectedFinding.ocsf.vulnerability.description} />
                          <DetailField label="Severity">
                            <span className={`severity-badge ${getSeverityBadgeClass(selectedFinding.ocsf.vulnerability.severity)}`}>
                              {selectedFinding.ocsf.vulnerability.severity}
                            </span>
                          </DetailField>
                          <DetailField label="Asset"     value={selectedFinding.ocsf.asset.name} />
                          <DetailField label="Source"    value={selectedFinding.source} />
                          <DetailField label="Detected"  value={new Date(selectedFinding.created_at).toLocaleString()} />
                          {selectedFinding.cvss_score != null && (
                            <DetailField label="CVSS3 Base Score">
                              <span className={`cvss-score-badge cvss-score-${getCvssScoreClass(selectedFinding.cvss_score)}`}>
                                {selectedFinding.cvss_score} — {getCvssScoreLabel(selectedFinding.cvss_score)}
                              </span>
                            </DetailField>
                          )}
                          {selectedFinding.cvss_vector && (
                            <DetailField label="CVSS3 Vector">
                              <code className="cvss-vector-code">{selectedFinding.cvss_vector}</code>
                            </DetailField>
                          )}
                          {selectedFinding.ocsf.vulnerability.remediation && (
                            <DetailField label="Remediation" value={selectedFinding.ocsf.vulnerability.remediation} />
                          )}
                        </div>

                        {/* Right: risk exception form */}
                        <div className="finding-risk-section">
                          <h3>Risk Exception</h3>
                          <div className="exception-type-group">
                            {[
                              ['false_positive',        'False Positive'],
                              ['operational_requirement','Operational Requirement'],
                              ['vendor_dependency',      'Vendor Dependency'],
                              ['risk_adjustment',        'Risk Adjustment'],
                            ].map(([val, lbl]) => (
                              <label key={val} className={`exception-type-option${exceptionType === val ? ' active' : ''}`}>
                                <input
                                  type="radio"
                                  name="exceptionType"
                                  value={val}
                                  checked={exceptionType === val}
                                  onChange={() => { setExceptionType(val); setShowCvssCalc(false); }}
                                />
                                {lbl}
                              </label>
                            ))}
                          </div>

                          {exceptionType && (
                            <div className="exception-fields">
                              <label className="exception-label">Justification</label>
                              <textarea
                                rows={4}
                                placeholder="Describe the justification for this risk exception…"
                                value={exceptionJustification}
                                onChange={e => setExceptionJustification(e.target.value)}
                              />
                              {exceptionType === 'risk_adjustment' && selectedFinding.cvss_score != null && (
                                <button
                                  type="button"
                                  className="cvss-calc-toggle-btn"
                                  onClick={() => setShowCvssCalc(v => !v)}
                                >
                                  {showCvssCalc ? '▲ Hide' : '▼ Open'} Environmental Risk Calculator
                                </button>
                              )}
                              <div className="exception-actions">
                                <button type="button" onClick={handleSaveException}>Save Exception</button>
                                <button type="button" className="btn-secondary" onClick={() => { setExceptionType(''); setExceptionJustification(''); setShowCvssCalc(false); }}>
                                  Cancel
                                </button>
                              </div>
                            </div>
                          )}
                        </div>
                      </div>

                      {/* CVSS Environmental Calculator */}
                      {showCvssCalc && (
                        <div className="cvss-calculator-wrapper">
                          <div className="cvss-sticky-scores">
                            <div className="cvss-score-row">
                              <div className="cvss-score-item">
                                <div className="cvss-score-label">Base Score</div>
                                <div className={`cvss-score-value cvss-score-${getCvssScoreClass(selectedFinding.cvss_score)}`}>
                                  {selectedFinding.cvss_score}
                                </div>
                                <div className="cvss-score-severity">{getCvssScoreLabel(selectedFinding.cvss_score)}</div>
                              </div>
                              <div className="cvss-score-arrow">→</div>
                              <div className="cvss-score-item">
                                <div className="cvss-score-label">Adjusted Score</div>
                                <div className={`cvss-score-value cvss-score-${getCvssScoreClass(adjustedCvssScore)}`}>
                                  {adjustedCvssScore !== null ? adjustedCvssScore : '—'}
                                </div>
                                <div className="cvss-score-severity">{getCvssScoreLabel(adjustedCvssScore)}</div>
                              </div>
                            </div>
                            {selectedFinding.cvss_vector && (
                              <div className="cvss-base-vector">Base vector: {selectedFinding.cvss_vector}</div>
                            )}
                          </div>
                          <div className="cvss-metrics-scroll">
                            {CVSS_ENV_METRICS.map(({ group, items }) => (
                              <div key={group} className="cvss-metric-group">
                                <div className="cvss-metric-group-title">{group}</div>
                                {items.map(({ key, label, opts }) => (
                                  <div key={key} className="cvss-metric-row">
                                    <label className="cvss-metric-label">{label}</label>
                                    <select
                                      className="cvss-metric-select"
                                      value={cvssEnv[key]}
                                      onChange={e => setCvssEnv(prev => ({ ...prev, [key]: e.target.value }))}
                                    >
                                      {opts.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                                    </select>
                                  </div>
                                ))}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </>
          )}

          {currentTab === 'ingest' && (
            <>
              <section className="panel">
                <h2>Data Ingest</h2>
                <form onSubmit={handleIngest}>
                  <input type="file" accept=".csv,.json,.xml" onChange={(e) => setFile(e.target.files?.[0] || null)} />
                  <button type="submit">Ingest</button>
                </form>
              </section>
            </>
          )}

          {currentTab === 'reports' && (
            <>
              <section className="panel">
                <h2>Vulnerability Reports</h2>
                <div className="mb-8">
                  <div className="text-gray-600">Overview of active vulnerabilities and remediation status</div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
                  <div className="lg:col-span-1 bg-white border border-gray-200 rounded-lg p-6">
                    <h2 className="text-lg mb-4">Severity Distribution</h2>
                    <ResponsiveContainer width="100%" height={300}>
                      <PieChart>
                        <Pie
                          data={severityCounts}
                          cx="50%"
                          cy="50%"
                          labelLine={false}
                          label={({ name, value }) => `${name}: ${value}`}
                          outerRadius={100}
                          dataKey="value"
                        >
                          {severityCounts.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip />
                        <Legend />
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="mt-4 pt-4 border-t border-gray-200">
                      <div className="grid grid-cols-5 gap-2 text-center">
                        <div>
                          <div className="text-lg" style={{ color: '#dc2626' }}>{severityCounts[0].value}</div>
                          <div className="text-xs text-gray-600 mt-1">Critical</div>
                        </div>
                        <div>
                          <div className="text-lg" style={{ color: '#ef4444' }}>{severityCounts[1].value}</div>
                          <div className="text-xs text-gray-600 mt-1">High</div>
                        </div>
                        <div>
                          <div className="text-lg" style={{ color: '#f59e0b' }}>{severityCounts[2].value}</div>
                          <div className="text-xs text-gray-600 mt-1">Medium</div>
                        </div>
                        <div>
                          <div className="text-lg" style={{ color: '#3b82f6' }}>{severityCounts[3].value}</div>
                          <div className="text-xs text-gray-600 mt-1">Low</div>
                        </div>
                        <div>
                          <div className="text-lg" style={{ color: '#6b7280' }}>{severityCounts[4].value}</div>
                          <div className="text-xs text-gray-600 mt-1">Unknown</div>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="lg:col-span-2 grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="bg-white border border-gray-200 rounded-lg p-6">
                      <h2 className="text-lg mb-4">Recent Critical Priority</h2>
                      <div className="max-h-[280px] overflow-y-auto">
                        <VulnerabilityList items={findings.filter(f => f.ocsf.vulnerability.severity === 'Critical').slice(0, 5)} />
                      </div>
                    </div>

                    <div className="bg-white border border-gray-200 rounded-lg p-6">
                      <h2 className="text-lg mb-4">Recent Unknown Priority</h2>
                      <div className="max-h-[280px] overflow-y-auto">
                        <VulnerabilityList items={findings.filter(f => !['Critical', 'High', 'Medium', 'Low'].includes(f.ocsf.vulnerability.severity)).slice(0, 5)} />
                      </div>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
                  <div className="bg-white border border-gray-200 rounded-lg p-6">
                    <div className="flex items-center gap-2 mb-4">
                      <div className="w-3 h-3 rounded-full bg-red-700"></div>
                      <h2 className="text-lg">Critical Severity</h2>
                      <span className="ml-auto text-2xl text-red-700">{findings.filter(f => f.ocsf.vulnerability.severity === 'Critical').length}</span>
                    </div>
                    <div className="max-h-[400px] overflow-y-auto">
                      <VulnerabilityList items={findings.filter(f => f.ocsf.vulnerability.severity === 'Critical')} />
                    </div>
                  </div>

                  <div className="bg-white border border-gray-200 rounded-lg p-6">
                    <div className="flex items-center gap-2 mb-4">
                      <div className="w-3 h-3 rounded-full bg-red-500"></div>
                      <h2 className="text-lg">High Severity</h2>
                      <span className="ml-auto text-2xl text-red-600">{findings.filter(f => f.ocsf.vulnerability.severity === 'High').length}</span>
                    </div>
                    <div className="max-h-[400px] overflow-y-auto">
                      <VulnerabilityList items={findings.filter(f => f.ocsf.vulnerability.severity === 'High')} />
                    </div>
                  </div>

                  <div className="bg-white border border-gray-200 rounded-lg p-6">
                    <div className="flex items-center gap-2 mb-4">
                      <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                      <h2 className="text-lg">Medium Severity</h2>
                      <span className="ml-auto text-2xl text-yellow-600">{findings.filter(f => f.ocsf.vulnerability.severity === 'Medium').length}</span>
                    </div>
                    <div className="max-h-[400px] overflow-y-auto">
                      <VulnerabilityList items={findings.filter(f => f.ocsf.vulnerability.severity === 'Medium')} />
                    </div>
                  </div>

                  <div className="bg-white border border-gray-200 rounded-lg p-6">
                    <div className="flex items-center gap-2 mb-4">
                      <div className="w-3 h-3 rounded-full bg-blue-500"></div>
                      <h2 className="text-lg">Low Severity</h2>
                      <span className="ml-auto text-2xl text-blue-600">{findings.filter(f => f.ocsf.vulnerability.severity === 'Low').length}</span>
                    </div>
                    <div className="max-h-[400px] overflow-y-auto">
                      <VulnerabilityList items={findings.filter(f => f.ocsf.vulnerability.severity === 'Low')} />
                    </div>
                  </div>

                  <div className="bg-white border border-gray-200 rounded-lg p-6">
                    <div className="flex items-center gap-2 mb-4">
                      <div className="w-3 h-3 rounded-full bg-gray-500"></div>
                      <h2 className="text-lg">Unknown Severity</h2>
                      <span className="ml-auto text-2xl text-gray-600">{findings.filter(f => !['Critical', 'High', 'Medium', 'Low'].includes(f.ocsf.vulnerability.severity)).length}</span>
                    </div>
                    <div className="max-h-[400px] overflow-y-auto">
                      <VulnerabilityList items={findings.filter(f => !['Critical', 'High', 'Medium', 'Low'].includes(f.ocsf.vulnerability.severity))} />
                    </div>
                  </div>
                </div>
              </section>
            </>
          )}

          {currentTab === 'admin' && (
            <>
              <section className="panel">
                <h2>CISA KEV Download & Import</h2>
                <button type="button" onClick={handleKevIngest}>Download and Import KEV</button>
              </section>

              <section className="panel actions">
                <button type="button" onClick={handlePopulateCvss}>Populate CVSS</button>
              </section>
            </>
          )}
        </>
      )}
    </div>
  );
}

export default App;

import { useEffect, useMemo, useState } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';
import logoSrc from './logo-vanquish.png';

const apiBase = import.meta.env.VITE_API_BASE || '/api';

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

  const handleFilter = (column, value) => {
    console.log('Filtering', column, value);
    setFilters(prev => ({
      ...prev,
      [column]: value
    }));
  };

  const clearFilter = (column) => {
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
                  <span className={`px-2 py-0.5 text-xs rounded border ${finding.ocsf.vulnerability.severity === 'High' ? 'bg-red-50 text-red-900 border-red-200' : finding.ocsf.vulnerability.severity === 'Medium' ? 'bg-amber-50 text-amber-900 border-amber-200' : 'bg-blue-50 text-blue-900 border-blue-200'}`}>
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
              <h2><strong>V</strong>ulnerablity <strong>A</strong>ssessment & <strong>N</strong>on-compliance <strong>Q</strong>ueue - <strong>U</strong>nified <strong>I</strong>ssue <strong>S</strong>tatus <strong>H</strong>ub</h2>
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
                <h2>Stored Findings</h2>
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
                      {filteredFindings.length === 0 && (
                        <tr>
                          <td colSpan="7">No findings stored yet.</td>
                        </tr>
                      )}
                      {filteredFindings.map((finding) => (
                        <tr key={finding.id} onClick={() => setSelectedFinding(finding)} style={{ cursor: 'pointer' }}>
                          <td className="px-4 py-3">{finding.id}</td>
                          <td className="px-4 py-3">{finding.ocsf.asset.name}</td>
                          <td className="px-4 py-3">{finding.ocsf.vulnerability.severity}</td>
                          <td className="px-4 py-3">{finding.ocsf.vulnerability.title}</td>
                          <td className="px-4 py-3">{finding.ocsf.vulnerability.detector_id || 'N/A'}</td>
                          <td className="px-4 py-3">{finding.source}</td>
                          <td className="px-4 py-3">{new Date(finding.created_at).toLocaleString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>

              {selectedFinding && (
                <section className="panel">
                  <h2>Vulnerability Details</h2>
                  <pre>{JSON.stringify(selectedFinding.ocsf, null, 2)}</pre>
                  <button onClick={() => setSelectedFinding(null)}>Close</button>
                </section>
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

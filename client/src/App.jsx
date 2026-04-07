import { useEffect, useState } from 'react';

const apiBase = import.meta.env.VITE_API_BASE || '/api';

function App() {
  const [findings, setFindings] = useState([]);
  const [csvFile, setCsvFile] = useState(null);
  const [jsonText, setJsonText] = useState('[]');
  const [message, setMessage] = useState('');
  const [isDark, setIsDark] = useState(false);

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

  useEffect(() => {
    fetchFindings();
  }, []);

  const fetchFindings = async () => {
    const response = await fetch(`${apiBase}/vulnerabilities`);
    const data = await response.json();
    setFindings(data.findings || []);
  };

  const handleCsvUpload = async (event) => {
    event.preventDefault();
    if (!csvFile) {
      setMessage('Please choose a CSV file first.');
      return;
    }
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

  const handleJsonUpload = async (event) => {
    event.preventDefault();
    try {
      const body = JSON.parse(jsonText);
      const response = await fetch(`${apiBase}/upload/json`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      });
      const data = await response.json();
      if (response.ok) {
        setMessage(`Imported ${data.imported} JSON records.`);
        fetchFindings();
      } else {
        setMessage(data.error || 'Upload failed.');
      }
    } catch (error) {
      setMessage('Invalid JSON payload.');
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

  return (
    <div className="app-shell">
      <button className="theme-toggle" onClick={toggleTheme}>
        {isDark ? '☀️' : '🌙'}
      </button>
      <header>
        <h1>Vanquish Vulnerability Manager</h1>
        <p>Upload CSV/JSON vulnerability reports, store as OCSF, and export POA&M.</p>
      </header>

      <section className="panel">
        <h2>CSV Import</h2>
        <form onSubmit={handleCsvUpload}>
          <input type="file" accept="text/csv" onChange={(e) => setCsvFile(e.target.files?.[0] || null)} />
          <button type="submit">Upload CSV</button>
        </form>
      </section>

      <section className="panel">
        <h2>JSON Import</h2>
        <form onSubmit={handleJsonUpload}>
          <textarea value={jsonText} onChange={(e) => setJsonText(e.target.value)} rows={10} />
          <button type="submit">Upload JSON</button>
        </form>
      </section>

      <section className="panel actions">
        <button type="button" onClick={fetchFindings}>Refresh Findings</button>
        <button type="button" onClick={exportPoam}>Export POA&M</button>
      </section>

      {message && <div className="message">{message}</div>}

      <section className="panel">
        <h2>Stored Findings</h2>
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Asset</th>
                <th>Severity</th>
                <th>Vulnerability</th>
                <th>Source</th>
                <th>Detected</th>
              </tr>
            </thead>
            <tbody>
              {findings.length === 0 && (
                <tr>
                  <td colSpan="6">No findings stored yet.</td>
                </tr>
              )}
              {findings.map((finding) => (
                <tr key={finding.id}>
                  <td>{finding.id}</td>
                  <td>{finding.ocsf.asset.name}</td>
                  <td>{finding.ocsf.vulnerability.severity}</td>
                  <td>{finding.ocsf.vulnerability.title}</td>
                  <td>{finding.source}</td>
                  <td>{new Date(finding.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

export default App;

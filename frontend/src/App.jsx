
import { useState } from 'react'
import {
  LayoutDashboard, BrainCircuit, ShieldCheck,
  ChartNoAxesCombined, FileText, Menu, Bell, Upload,
  Activity, CheckCircle2, AlertTriangle, RefreshCw, Database
} from 'lucide-react'
import {
  ResponsiveContainer, AreaChart, Area, CartesianGrid, XAxis, YAxis,
  Tooltip, PieChart, Pie, Cell
} from 'recharts'

const API_URL = ''

const navigation = [
  { label: 'Dashboard', icon: LayoutDashboard },
  { label: 'Dataset Processing', icon: Database },
  { label: 'Attack Classification', icon: BrainCircuit },
  { label: 'Firewall Simulation', icon: ShieldCheck },
  { label: 'Monitoring & Analytics', icon: ChartNoAxesCombined },
  { label: 'Unified Reporting', icon: FileText }
]

const chartColors = [
  '#69a985', '#e4b66a', '#d97878',
  '#7797c9', '#9b83bd', '#d58a62'
]

const traffic = [
  { time: '09:00', normal: 32, suspicious: 5 },
  { time: '10:00', normal: 48, suspicious: 9 },
  { time: '11:00', normal: 42, suspicious: 7 },
  { time: '12:00', normal: 65, suspicious: 13 },
  { time: '13:00', normal: 55, suspicious: 8 },
  { time: '14:00', normal: 78, suspicious: 16 },
  { time: '15:00', normal: 68, suspicious: 11 }
]

// Explanations and recommendations are general security guidance.
const threatInformation = {
  normal: {
    name: 'Normal Traffic',
    effects: 'No attack category was predicted for this traffic. This does not guarantee that the traffic is completely risk-free.',
    recommendation: 'Continue routine monitoring, maintain security updates, and review unusual traffic patterns.'
  },
  dos: {
    name: 'Denial of Service (DoS)',
    effects: 'DoS activity can overwhelm network resources, slow services, and make applications unavailable to legitimate users.',
    recommendation: 'Monitor traffic volume, apply rate limiting, review unusual connection spikes, and use appropriate network protection.'
  },
  ddos: {
    name: 'Distributed Denial of Service (DDoS)',
    effects: 'DDoS activity can overwhelm services with traffic from multiple sources and interrupt service availability.',
    recommendation: 'Use DDoS protection services, traffic monitoring, rate limiting, and an incident response plan.'
  },
  exploits: {
    name: 'Exploits',
    effects: 'Exploit attempts may target software weaknesses and could lead to unauthorized access or system compromise.',
    recommendation: 'Patch vulnerable software, review affected systems, restrict unnecessary access, and investigate suspicious activity.'
  },
  generic: {
    name: 'Generic Attack',
    effects: 'This category represents attack patterns that may affect systems in different ways, including possible service or application compromise.',
    recommendation: 'Investigate affected traffic, review endpoint logs, update security controls, and monitor related activity.'
  },
  fuzzers: {
    name: 'Fuzzers',
    effects: 'Fuzzing activity sends unusual or unexpected inputs to applications and may reveal software weaknesses or cause instability.',
    recommendation: 'Validate application inputs, review application logs, and test and patch affected software.'
  },
  reconnaissance: {
    name: 'Reconnaissance',
    effects: 'Reconnaissance activity may indicate attempts to discover hosts, services, or network information before another attack.',
    recommendation: 'Review scanning activity, restrict unnecessary exposed services, and monitor repeated connection attempts.'
  },
  analysis: {
    name: 'Analysis',
    effects: 'This category may represent suspicious analysis or probing activity that could help an attacker understand network services.',
    recommendation: 'Review the source and destination activity, inspect relevant logs, and limit unnecessary service exposure.'
  },
  backdoor: {
    name: 'Backdoor',
    effects: 'Backdoor activity may indicate an attempt to maintain unauthorized access to a system.',
    recommendation: 'Investigate affected endpoints, review access logs, check system integrity, and follow your incident response process.'
  },
  shellcode: {
    name: 'Shellcode',
    effects: 'Shellcode-related activity may indicate an attempt to execute unauthorized code or exploit a software weakness.',
    recommendation: 'Investigate the affected host, apply security updates, and review endpoint security alerts.'
  },
  worms: {
    name: 'Worms',
    effects: 'Worm activity may spread between systems and can affect network availability and system integrity.',
    recommendation: 'Investigate affected devices, isolate confirmed compromised systems through approved procedures, and apply security updates.'
  }
}

function normalizeName(value) {
  return String(value ?? '').trim().toLowerCase()
}

function getThreatInfo(category) {
  const name = normalizeName(category)

  if (name === 'normal' || name === '0' || name === 'benign') {
    return threatInformation.normal
  }

  for (const [key, value] of Object.entries(threatInformation)) {
    if (key !== 'normal' && name.includes(key)) return value
  }

  return {
    name: String(category),
    effects: 'The model identified this category as non-normal traffic. Its exact impact depends on the activity and affected system.',
    recommendation: 'Review the relevant network and system logs, investigate the source and destination, and apply your organization’s security procedures.'
  }
}

function getAnalysis(result) {
  const categories = result?.predicted_categories || {}

  const categoryData = Object.entries(categories).map(([name, count]) => ({
    name,
    value: Number(count) || 0
  }))

  const totalRecords = Number(result?.total_records) ||
    categoryData.reduce((sum, item) => sum + item.value, 0)

  const isNormal = name =>
    ['normal', '0', 'benign'].includes(normalizeName(name))

  const normalCount = categoryData
    .filter(item => isNormal(item.name))
    .reduce((sum, item) => sum + item.value, 0)

  const threatCount = Math.max(0, totalRecords - normalCount)

  const threatPercentage = totalRecords > 0
    ? (threatCount / totalRecords) * 100
    : 0

  const attackCategories = categoryData
    .filter(item => !isNormal(item.name) && item.value > 0)
    .sort((a, b) => b.value - a.value)

  const highestThreat = attackCategories[0] || null

  // This is a heuristic indicator, NOT proof of data exposure.
  // It counts predictions in categories that may involve compromise
  // or unauthorized access. Network-flow data cannot confirm leakage.
  const possibleDataExposureCategories = [
    'exploits', 'backdoor', 'shellcode', 'generic', 'worms'
  ]

  const possibleExposureCount = categoryData
    .filter(item => {
      const name = normalizeName(item.name)
      return possibleDataExposureCategories.some(key => name.includes(key))
    })
    .reduce((sum, item) => sum + item.value, 0)

  const sensitiveDataPercentage = totalRecords > 0
    ? (possibleExposureCount / totalRecords) * 100
    : 0

  return {
    categoryData,
    totalRecords,
    normalCount,
    threatCount,
    threatPercentage,
    attackCategories,
    highestThreat,
    possibleExposureCount,
    sensitiveDataPercentage
  }
}

function Stat({ title, value, note, icon: Icon }) {
  return (
    <section className="stat-card">
      <div className="stat-top">
        <span>{title}</span>
        <span className="stat-icon"><Icon size={18}/></span>
      </div>
      <strong>{value}</strong>
      <small>{note}</small>
    </section>
  )
}

function ThreatDetails({ category }) {
  const info = getThreatInfo(category)

  return (
    <section className="panel" style={{ padding: 20, marginTop: 18 }}>
      <h3>{info.name}</h3>
      <p><strong>Possible effects:</strong></p>
      <p>{info.effects}</p>
      <p><strong>Recommended action:</strong></p>
      <p>{info.recommendation}</p>
    </section>
  )
}

function ResultsOverview({ result }) {
  const analysis = getAnalysis(result)
  const highest = analysis.highestThreat
  const info = highest ? getThreatInfo(highest.name) : threatInformation.normal

  return (
    <>
      <div className="stats-grid">
        <Stat
          title="Total Records"
          value={analysis.totalRecords}
          note="Records analyzed"
          icon={Activity}
        />
        <Stat
          title="Normal Traffic"
          value={analysis.normalCount}
          note="Predicted normal records"
          icon={CheckCircle2}
        />
        <Stat
          title="Detected Threats"
          value={analysis.threatCount}
          note={`${analysis.threatPercentage.toFixed(1)}% of total traffic`}
          icon={AlertTriangle}
        />
        <Stat
          title="Threat Level"
          value={`${analysis.threatPercentage.toFixed(1)}%`}
          note="Based on non-normal predictions"
          icon={ShieldCheck}
        />
      </div>

      <div className="charts-grid">
        <section className="panel chart-panel">
          <div className="panel-title">
            <div>
              <h3>Threat Percentage</h3>
              <p>Share of records predicted as non-normal</p>
            </div>
          </div>

          <div style={{ padding: 24, textAlign: 'center' }}>
            <strong style={{ fontSize: 42, color: '#d97878' }}>
              {analysis.threatPercentage.toFixed(1)}%
            </strong>
            <p className="muted">
              {analysis.threatCount} potential threats out of {analysis.totalRecords} records
            </p>
          </div>
        </section>

        <section className="panel chart-panel">
          <div className="panel-title">
            <div>
              <h3>Sensitive Data Alert</h3>
              <p>Estimated indicator based on selected attack categories</p>
            </div>
          </div>

          <div style={{ padding: 24, textAlign: 'center' }}>
            <strong style={{ fontSize: 42, color: '#d9aa5c' }}>
              {analysis.sensitiveDataPercentage.toFixed(1)}%
            </strong>
            <p className="muted">
              {analysis.possibleExposureCount} records in potentially relevant categories
            </p>
          </div>
        </section>
      </div>

      <section className="panel" style={{ padding: 20, marginTop: 18 }}>
        <h3>Highest Detected Threat</h3>
        {highest ? (
          <>
            <h2 style={{ color: '#d97878' }}>{info.name}</h2>
            <p>
              {highest.value} records · {(
                highest.value / Math.max(analysis.totalRecords, 1) * 100
              ).toFixed(1)}% of all records
            </p>
            <ThreatDetails category={highest.name}/>
          </>
        ) : (
          <p>No non-normal predictions were reported by the model.</p>
        )}
      </section>

      <section className="panel" style={{ padding: 20, marginTop: 18 }}>
        <h3>All Detected Threats and Recommendations</h3>

        {analysis.attackCategories.length === 0 ? (
          <p>No attack categories were detected.</p>
        ) : (
          analysis.attackCategories.map(item => {
            const threat = getThreatInfo(item.name)
            const percentage = analysis.totalRecords > 0
              ? item.value / analysis.totalRecords * 100
              : 0

            return (
              <div key={item.name} style={{
                padding: '14px 0',
                borderBottom: '1px solid #e8eee9'
              }}>
                <div style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  gap: 12,
                  flexWrap: 'wrap'
                }}>
                  <strong>{threat.name}</strong>
                  <strong>{percentage.toFixed(1)}%</strong>
                </div>

                <p>{item.value} predicted records</p>
                <p><strong>Effects:</strong> {threat.effects}</p>
                <p><strong>Suggestion:</strong> {threat.recommendation}</p>
              </div>
            )
          })
        )}
      </section>

      <p className="muted" style={{ marginTop: 16 }}>
        Important: Threat level is calculated from prediction counts, not model
        confidence. The sensitive-data alert is an estimated indicator, not
        confirmed evidence of sensitive information being accessed or leaked.
      </p>
    </>
  )
}

function Dashboard({ result }) {
  const analysis = result ? getAnalysis(result) : null

  return (
    <>
      <div className="page-heading">
        <div>
          <h2>Security Dashboard</h2>
          <p>Overview of your network intrusion detection system</p>
        </div>
      </div>

      {analysis ? (
        <>
          <ResultsOverview result={result}/>

          <section className="panel table-panel">
            <div className="panel-title">
              <div>
                <h3>Dataset Information</h3>
                <p>Current uploaded dataset</p>
              </div>
              <span className="tag">Analyzed</span>
            </div>
            <p>File: {result.filename}</p>
            <p>Total records: {analysis.totalRecords}</p>
            <p>Model: Random Forest</p>
          </section>
        </>
      ) : (
        <>
          <div className="stats-grid">
            <Stat title="Total Network Traffic" value="—" note="Upload a dataset to begin" icon={Activity}/>
            <Stat title="Normal Traffic" value="—" note="Waiting for analysis" icon={CheckCircle2}/>
            <Stat title="Threats Detected" value="—" note="Waiting for analysis" icon={AlertTriangle}/>
            <Stat title="System Status" value="Ready" note="Waiting for dataset" icon={ShieldCheck}/>
          </div>

          <div className="charts-grid">
            <section className="panel chart-panel">
              <div className="panel-title">
                <div>
                  <h3>Network Traffic Analysis</h3>
                  <p>Illustrative sample data</p>
                </div>
                <span className="tag">Demo data</span>
              </div>
              <div className="chart">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={traffic}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#e8eee9"/>
                    <XAxis dataKey="time" tickLine={false} axisLine={false}/>
                    <YAxis tickLine={false} axisLine={false}/>
                    <Tooltip/>
                    <Area type="monotone" dataKey="normal" stroke="#69a985" fill="#69a985" fillOpacity={0.18} strokeWidth={2}/>
                    <Area type="monotone" dataKey="suspicious" stroke="#d9aa5c" fill="#d9aa5c" fillOpacity={0.16} strokeWidth={2}/>
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </section>

            <section className="panel chart-panel">
              <div className="panel-title">
                <div>
                  <h3>Traffic Classification</h3>
                  <p>Upload a dataset to see actual predictions</p>
                </div>
              </div>
              <p className="muted">No dataset analyzed yet.</p>
            </section>
          </div>
        </>
      )}
    </>
  )
}

function ModulePage({ page, result }) {
  const analysis = result ? getAnalysis(result) : null

  const descriptions = {
    'Dataset Processing': [
      'Network Traffic Dataset Processing',
      'Dataset information and processing results from your uploaded CSV.'
    ],
    'Attack Classification': [
      'Machine Learning-Based Attack Classification',
      'Predicted network attack categories from the Random Forest model.'
    ],
    'Firewall Simulation': [
      'Firewall Rule Simulation',
      'Review simulated allow, review, and block decisions.'
    ],
    'Monitoring & Analytics': [
      'Intrusion Monitoring and Analytics',
      'Threat percentages, attack distribution, and security indicators.'
    ],
    'Unified Reporting': [
      'Unified Reporting',
      'Complete network security assessment based on model predictions.'
    ]
  }

  const [title, description] = descriptions[page] || [page, '']

  if (!result || !analysis) {
    return (
      <>
        <div className="page-heading">
          <div>
            <h2>{title}</h2>
            <p>{description}</p>
          </div>
        </div>
        <section className="panel module-panel">
          <div className="upload-icon"><Upload size={24}/></div>
          <h3>No dataset analyzed yet</h3>
          <p className="muted">
            Upload your CSV once using the shared upload section above.
            The results will automatically appear in this module.
          </p>
        </section>
      </>
    )
  }

  const categoryData = analysis.categoryData
  const highest = analysis.highestThreat
  const threatInfo = highest ? getThreatInfo(highest.name) : threatInformation.normal

  return (
    <>
      <div className="page-heading">
        <div>
          <h2>{title}</h2>
          <p>{description}</p>
        </div>
      </div>

      <section className="panel module-panel">
        <h3>Analysis Results</h3>
        <p>Dataset: {result.filename}</p>
        <p>Total records: {analysis.totalRecords}</p>
        <p>Model: Random Forest</p>
        <p className="muted">{result.message}</p>

        {page === 'Dataset Processing' && (
          <>
            <h3 style={{ marginTop: 24 }}>Dataset Summary</h3>
            <p>Successfully analyzed records: {analysis.totalRecords}</p>
            <p>Predicted categories: {categoryData.length}</p>
            <p>Normal records: {analysis.normalCount}</p>
            <p>Potential threat records: {analysis.threatCount}</p>
          </>
        )}

        {page === 'Attack Classification' && (
          <>
            <h3 style={{ marginTop: 24 }}>Attack Classification Results</h3>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Attack Category</th>
                    <th>Predicted Records</th>
                    <th>Percentage</th>
                  </tr>
                </thead>
                <tbody>
                  {categoryData.map(item => (
                    <tr key={item.name}>
                      <td>{item.name}</td>
                      <td>{item.value}</td>
                      <td>
                        {analysis.totalRecords
                          ? (item.value / analysis.totalRecords * 100).toFixed(1)
                          : '0.0'}%
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {highest && <ThreatDetails category={highest.name}/>}
          </>
        )}

        {page === 'Monitoring & Analytics' && (
          <>
            <ResultsOverview result={result}/>

            <section className="panel chart-panel" style={{ marginTop: 20 }}>
              <div className="panel-title">
                <div>
                  <h3>Predicted Traffic Distribution</h3>
                  <p>Classification counts from the uploaded dataset</p>
                </div>
              </div>

              <div className="pie-wrap">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={categoryData}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={58}
                      outerRadius={88}
                      paddingAngle={3}
                    >
                      {categoryData.map((item, index) => (
                        <Cell
                          key={item.name}
                          fill={chartColors[index % chartColors.length]}
                        />
                      ))}
                    </Pie>
                    <Tooltip/>
                  </PieChart>
                </ResponsiveContainer>
              </div>

              <div className="legend">
                {categoryData.map((item, index) => (
                  <span key={item.name}>
                    <i style={{
                      background: chartColors[index % chartColors.length]
                    }}/>
                    {item.name} · {item.value}
                  </span>
                ))}
              </div>
            </section>
          </>
        )}

        {page === 'Firewall Simulation' && (
          <>
            <h3 style={{ marginTop: 24 }}>Simulated Firewall Decisions</h3>
            <p className="muted">
              These are demonstration decisions based on model predictions.
              No real firewall configuration is changed.
            </p>

            <div className="stats-grid">
              <Stat
                title="Allow"
                value={analysis.normalCount}
                note="Normal predictions"
                icon={CheckCircle2}
              />
              <Stat
                title="Block"
                value={analysis.attackCategories
                  .filter(item => {
                    const n = normalizeName(item.name)
                    return ['dos', 'ddos', 'exploits', 'backdoor', 'shellcode', 'worms']
                      .some(key => n.includes(key))
                  })
                  .reduce((sum, item) => sum + item.value, 0)}
                note="Higher-risk attack categories"
                icon={ShieldCheck}
              />
              <Stat
                title="Review"
                value={analysis.attackCategories
                  .filter(item => {
                    const n = normalizeName(item.name)
                    return !['dos', 'ddos', 'exploits', 'backdoor', 'shellcode', 'worms']
                      .some(key => n.includes(key))
                  })
                  .reduce((sum, item) => sum + item.value, 0)}
                note="Other non-normal predictions"
                icon={AlertTriangle}
              />
            </div>

            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Predicted Category</th>
                    <th>Records</th>
                    <th>Simulated Action</th>
                  </tr>
                </thead>
                <tbody>
                  {categoryData.map(item => {
                    const n = normalizeName(item.name)
                    const normal = ['normal', '0', 'benign'].includes(n)
                    const highRisk = ['dos', 'ddos', 'exploits', 'backdoor', 'shellcode', 'worms']
                      .some(key => n.includes(key))
                    const action = normal ? 'Allow' : highRisk ? 'Block' : 'Review'

                    return (
                      <tr key={item.name}>
                        <td>{item.name}</td>
                        <td>{item.value}</td>
                        <td>
                          <span className={`pill ${
                            action === 'Allow' ? 'success' :
                            action === 'Review' ? 'warning' : 'danger'
                          }`}>
                            {action}
                          </span>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </>
        )}

        {page === 'Unified Reporting' && (
          <>
            <h3 style={{ marginTop: 24 }}>Network Security Assessment Report</h3>
            <ResultsOverview result={result}/>

            <h3 style={{ marginTop: 24 }}>Classification Summary</h3>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Category</th>
                    <th>Predicted Records</th>
                  </tr>
                </thead>
                <tbody>
                  {categoryData.map(item => (
                    <tr key={item.name}>
                      <td>{item.name}</td>
                      <td>{item.value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <button
              className="primary-button"
              onClick={() => window.print()}
            >
              Print / Save Report as PDF
            </button>
          </>
        )}
      </section>
    </>
  )
}

export default function App() {
  const [active, setActive] = useState('Dashboard')
  const [mobileOpen, setMobileOpen] = useState(false)

  // Shared upload and result state for the entire application.
  const [file, setFile] = useState(null)
  const [result, setResult] = useState(null)
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState('')

  async function handleUpload() {
    if (!file || uploading) return

    setUploading(true)
    setError('')
    setResult(null)

    try {
      const formData = new FormData()
      formData.append('file', file)

      // One request. Every module uses this shared response.
      const response = await fetch(`${API_URL}/api/predict`, {
        method: 'POST',
        body: formData
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.detail || 'Dataset analysis failed.')
      }

      if (!data.predicted_categories) {
        throw new Error(
          'The backend response does not contain predicted_categories.'
        )
      }

      setResult(data)
      setActive('Dashboard')
    } catch (err) {
      setError(err.message || 'Unable to connect to the backend.')
    } finally {
      setUploading(false)
    }
  }

  const current = navigation.find(item => item.label === active)
  const Icon = current?.icon || LayoutDashboard

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileOpen ? 'sidebar-open' : ''}`}>
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={22}/>
          </div>
          <div>
            <b>NEXUS</b>
            <small>NETWORK SECURITY</small>
          </div>
        </div>

        <div className="nav-label">ASSESSMENT MODULES</div>

        <nav>
          {navigation.map(item => {
            const I = item.icon

            return (
              <button
                key={item.label}
                className={`nav-item ${active === item.label ? 'active' : ''}`}
                onClick={() => {
                  setActive(item.label)
                  setMobileOpen(false)
                }}
              >
                <I size={17}/>
                <span>{item.label}</span>
              </button>
            )
          })}
        </nav>

        <div className="sidebar-bottom">
          <span className="status-dot"/>
          Local development environment
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <button
            className="mobile-menu"
            onClick={() => setMobileOpen(!mobileOpen)}
          >
            <Menu size={20}/>
          </button>

          <div className="topbar-title">
            <b>{active}</b>
            <small>
              Intelligent Machine Learning-Based Network Intrusion Detection System
            </small>
          </div>

          <div className="topbar-right">
            <span className="phase">
              <span className="status-dot"/>
              Phase 1: Frontend
            </span>
            <button className="icon-button" aria-label="Notifications">
              <Bell size={18}/>
            </button>
          </div>
        </header>

        <div className="content">

          {/* Shared upload area: upload once for all six modules. */}
          <section className="panel" style={{
            padding: 20,
            marginBottom: 24
          }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: 12,
              flexWrap: 'wrap'
            }}>
              <div className="upload-icon">
                <Upload size={23}/>
              </div>
              <div>
                <h3 style={{ margin: 0 }}>NEXUS Dataset Upload</h3>
                <p className="muted" style={{ margin: '5px 0 0' }}>
                  Upload your UNSW-NB15 CSV once to analyze it across all modules.
                </p>
              </div>
            </div>

            <label className="upload-zone" style={{
              display: 'flex',
              marginTop: 18
            }}>
              <input
                type="file"
                accept=".csv"
                onChange={event => {
                  setFile(event.target.files?.[0] || null)
                  setResult(null)
                  setError('')
                }}
              />
              <Upload size={22}/>
              <strong>{file ? file.name : 'Choose your CSV dataset'}</strong>
              <span>
                {file
                  ? `${(file.size / 1024 / 1024).toFixed(2)} MB`
                  : 'Click to browse files · CSV format'}
              </span>
            </label>

            <button
              className="primary-button"
              disabled={!file || uploading}
              onClick={handleUpload}
            >
              {uploading ? 'Analyzing Dataset...' :
                result ? 'Analyze New Dataset' : 'Upload & Analyze Dataset'}
            </button>

            {uploading && (
              <p className="muted">
                Random Forest is processing your dataset. Please wait.
              </p>
            )}

            {error && (
              <p style={{ color: '#c94c4c', marginTop: 12 }}>
                {error}
              </p>
            )}

            {result && (
              <p style={{ color: '#4c946b', marginTop: 12 }}>
                <CheckCircle2 size={15} style={{
                  display: 'inline',
                  verticalAlign: 'middle'
                }}/> Dataset analyzed successfully. All modules now share these results.
              </p>
            )}
          </section>

          {active === 'Dashboard'
            ? <Dashboard result={result}/>
            : <ModulePage page={active} result={result}/>
          }

          <footer>
            NEXUS Network Security · Academic project interface ·
            Threat and sensitive-data indicators are estimates based on model predictions
          </footer>
        </div>
      </main>
    </div>
  )
}

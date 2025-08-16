import { useState, useEffect } from 'react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { 
  Terminal, 
  Shield, 
  Search, 
  Target, 
  FileText, 
  Activity,
  Wifi,
  Lock,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Brain
} from 'lucide-react'

interface ScanResult {
  id: string
  target: string
  type: string
  status: string
  progress: number
  started_at: string
  results?: any
  error?: string
  ai_analysis?: string
}

interface WebSocketMessage {
  type: string
  scan_id?: string
  progress?: number
  status?: string
  results?: any
  error?: string
  message?: string
  timestamp: string
  target?: string
  scan_type?: string
  ai_analysis?: string
}

function App() {
  const [activeTab, setActiveTab] = useState('dashboard')
  const [scans, setScans] = useState<ScanResult[]>([])
  const [connectionStatus, setConnectionStatus] = useState<'connecting' | 'connected' | 'disconnected'>('disconnected')
  const [scanTarget, setScanTarget] = useState('')
  const [scanType, setScanType] = useState('quick')
  const [logs, setLogs] = useState<string[]>([])
  const [ws, setWs] = useState<WebSocket | null>(null)

  useEffect(() => {
    connectWebSocket()
    return () => {
      if (ws) {
        ws.close()
      }
    }
  }, [])

  const connectWebSocket = () => {
    setConnectionStatus('connecting')
    const websocket = new WebSocket('ws://localhost:8000/ws')
    
    websocket.onopen = () => {
      setConnectionStatus('connected')
      addLog('Connected to Devlin API')
    }
    
    websocket.onmessage = (event) => {
      const message: WebSocketMessage = JSON.parse(event.data)
      handleWebSocketMessage(message)
    }
    
    websocket.onclose = () => {
      setConnectionStatus('disconnected')
      addLog('Disconnected from API')
      setTimeout(connectWebSocket, 3000)
    }
    
    websocket.onerror = (error) => {
      addLog(`WebSocket error: ${error}`)
    }
    
    setWs(websocket)
  }

  const handleWebSocketMessage = (message: WebSocketMessage) => {
    addLog(`[${message.type}] ${message.message || JSON.stringify(message)}`)
    
    switch (message.type) {
      case 'scan_started':
        if (message.scan_id) {
          const newScan: ScanResult = {
            id: message.scan_id,
            target: message.target || scanTarget,
            type: message.scan_type || scanType,
            status: 'starting',
            progress: 0,
            started_at: message.timestamp
          }
          setScans(prev => [...prev, newScan])
        }
        break
      
      case 'scan_progress':
        if (message.scan_id) {
          setScans(prev => prev.map(scan => 
            scan.id === message.scan_id 
              ? { ...scan, progress: message.progress || 0, status: message.status || scan.status }
              : scan
          ))
        }
        break
      
      case 'scan_completed':
        if (message.scan_id) {
          setScans(prev => prev.map(scan => 
            scan.id === message.scan_id 
              ? { ...scan, status: 'completed', progress: 100, results: message.results }
              : scan
          ))
        }
        break
      
      case 'ai_analysis_started':
        addLog(`🤖 AI Analysis: ${message.message}`)
        break
      
      case 'ai_analysis_completed':
        if (message.scan_id) {
          addLog(`✅ AI Analysis completed for scan ${message.scan_id}`)
          setScans(prev => prev.map(scan => 
            scan.id === message.scan_id 
              ? { ...scan, ai_analysis: message.ai_analysis }
              : scan
          ))
        }
        break
      
      case 'ai_analysis_failed':
        addLog(`❌ AI Analysis failed: ${message.error}`)
        break
      
      case 'scan_failed':
        if (message.scan_id) {
          setScans(prev => prev.map(scan => 
            scan.id === message.scan_id 
              ? { ...scan, status: 'failed', error: message.error }
              : scan
          ))
        }
        break
    }
  }

  const addLog = (message: string) => {
    const timestamp = new Date().toLocaleTimeString()
    setLogs(prev => [...prev.slice(-99), `[${timestamp}] ${message}`])
  }

  const startScan = async () => {
    if (!scanTarget.trim()) return
    
    try {
      const params = new URLSearchParams()
      params.append('target', scanTarget)
      params.append('scan_type', scanType)
      
      const response = await fetch(`http://localhost:8000/scans/nmap?${params.toString()}`, {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer devlin-local-auth-token-change-me'
        }
      })
      
      if (response.ok) {
        addLog(`Started ${scanType} scan on ${scanTarget}`)
        setScanTarget('')
      } else {
        addLog(`Failed to start scan: ${response.statusText}`)
      }
    } catch (error) {
      addLog(`Error starting scan: ${error}`)
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'failed': return <XCircle className="h-4 w-4 text-red-500" />
      case 'running': return <Activity className="h-4 w-4 text-blue-500 animate-pulse" />
      default: return <Activity className="h-4 w-4 text-yellow-500" />
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'bg-green-500'
      case 'failed': return 'bg-red-500'
      case 'running': return 'bg-blue-500'
      default: return 'bg-yellow-500'
    }
  }

  return (
    <div className="min-h-screen bg-gray-900 text-green-400 font-mono">
      <div className="container mx-auto p-4">
        <header className="mb-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8 text-green-400" />
              <h1 className="text-3xl font-bold text-green-400">DEVLIN</h1>
              <Badge variant="outline" className="text-green-400 border-green-400">
                Pentesting Automation
              </Badge>
            </div>
            <div className="flex items-center space-x-2">
              <div className={`h-2 w-2 rounded-full ${
                connectionStatus === 'connected' ? 'bg-green-500' : 
                connectionStatus === 'connecting' ? 'bg-yellow-500' : 'bg-red-500'
              }`} />
              <span className="text-sm text-gray-400 capitalize">{connectionStatus}</span>
            </div>
          </div>
        </header>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
          <TabsList className="grid w-full grid-cols-5 bg-gray-800 border-gray-700">
            <TabsTrigger value="dashboard" className="data-[state=active]:bg-green-900 data-[state=active]:text-green-400">
              <Activity className="h-4 w-4 mr-2" />
              Dashboard
            </TabsTrigger>
            <TabsTrigger value="scans" className="data-[state=active]:bg-green-900 data-[state=active]:text-green-400">
              <Target className="h-4 w-4 mr-2" />
              Scans
            </TabsTrigger>
            <TabsTrigger value="recon" className="data-[state=active]:bg-green-900 data-[state=active]:text-green-400">
              <Search className="h-4 w-4 mr-2" />
              Recon
            </TabsTrigger>
            <TabsTrigger value="exploits" className="data-[state=active]:bg-green-900 data-[state=active]:text-green-400">
              <AlertTriangle className="h-4 w-4 mr-2" />
              Exploits
            </TabsTrigger>
            <TabsTrigger value="reports" className="data-[state=active]:bg-green-900 data-[state=active]:text-green-400">
              <FileText className="h-4 w-4 mr-2" />
              Reports
            </TabsTrigger>
          </TabsList>

          <TabsContent value="dashboard" className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Card className="bg-gray-800 border-gray-700">
                <CardHeader className="pb-2">
                  <CardTitle className="text-green-400 flex items-center">
                    <Target className="h-5 w-5 mr-2" />
                    Active Scans
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-green-400">
                    {scans.filter(s => s.status === 'running').length}
                  </div>
                </CardContent>
              </Card>
              
              <Card className="bg-gray-800 border-gray-700">
                <CardHeader className="pb-2">
                  <CardTitle className="text-green-400 flex items-center">
                    <CheckCircle className="h-5 w-5 mr-2" />
                    Completed
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-green-400">
                    {scans.filter(s => s.status === 'completed').length}
                  </div>
                </CardContent>
              </Card>
              
              <Card className="bg-gray-800 border-gray-700">
                <CardHeader className="pb-2">
                  <CardTitle className="text-green-400 flex items-center">
                    <AlertTriangle className="h-5 w-5 mr-2" />
                    Vulnerabilities
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-red-400">0</div>
                </CardContent>
              </Card>
            </div>

            <Card className="bg-gray-800 border-gray-700">
              <CardHeader>
                <CardTitle className="text-green-400 flex items-center">
                  <Terminal className="h-5 w-5 mr-2" />
                  Live Logs
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="bg-black p-4 rounded-md h-64 overflow-y-auto font-mono text-sm">
                  {logs.map((log, index) => (
                    <div key={index} className="text-green-400 mb-1">
                      {log}
                    </div>
                  ))}
                  {logs.length === 0 && (
                    <div className="text-gray-500">No logs yet...</div>
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="scans" className="space-y-4">
            <Card className="bg-gray-800 border-gray-700">
              <CardHeader>
                <CardTitle className="text-green-400">Start New Scan</CardTitle>
                <CardDescription className="text-gray-400">
                  Enter target IP or domain to begin scanning
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex space-x-2">
                  <Input
                    placeholder="192.168.1.1 or example.com"
                    value={scanTarget}
                    onChange={(e) => setScanTarget(e.target.value)}
                    className="bg-gray-900 border-gray-600 text-green-400"
                  />
                  <select
                    value={scanType}
                    onChange={(e) => setScanType(e.target.value)}
                    className="bg-gray-900 border border-gray-600 text-green-400 px-3 py-2 rounded-md"
                  >
                    <option value="quick">Quick Scan</option>
                    <option value="aggressive">Aggressive Scan</option>
                    <option value="top-ports">Top Ports</option>
                    <option value="full-tcp">Full TCP</option>
                  </select>
                  <Button 
                    onClick={startScan}
                    disabled={!scanTarget.trim() || connectionStatus !== 'connected'}
                    className="bg-green-700 hover:bg-green-600 text-white"
                  >
                    <Wifi className="h-4 w-4 mr-2" />
                    Scan
                  </Button>
                </div>
              </CardContent>
            </Card>

            <div className="space-y-4">
              {scans.map((scan) => (
                <Card key={scan.id} className="bg-gray-800 border-gray-700">
                  <CardHeader className="pb-2">
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-green-400 flex items-center">
                        {getStatusIcon(scan.status)}
                        <span className="ml-2">{scan.target}</span>
                        <Badge variant="outline" className="ml-2 text-xs">
                          {scan.type}
                        </Badge>
                      </CardTitle>
                      <Badge className={`${getStatusColor(scan.status)} text-white`}>
                        {scan.status}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent>
                    {scan.status === 'running' && (
                      <div className="space-y-2">
                        <Progress value={scan.progress} className="w-full" />
                        <div className="text-sm text-gray-400">
                          Progress: {scan.progress}%
                        </div>
                      </div>
                    )}
                    
                    {scan.status === 'completed' && scan.results && (
                      <div className="space-y-2">
                        <div className="text-sm text-gray-400">
                          Found {scan.results.ports?.length || 0} open ports
                        </div>
                        {scan.results.ports?.map((port: any, index: number) => (
                          <div key={index} className="flex items-center space-x-2 text-sm">
                            <Badge variant="outline" className="text-green-400">
                              {port.port}
                            </Badge>
                            <span className="text-gray-300">{port.service}</span>
                            <span className="text-gray-500">{port.version}</span>
                          </div>
                        ))}
                      </div>
                    )}
                    
                    {scan.status === 'failed' && (
                      <Alert className="border-red-500">
                        <AlertTriangle className="h-4 w-4" />
                        <AlertDescription className="text-red-400">
                          {scan.error || 'Scan failed'}
                        </AlertDescription>
                      </Alert>
                    )}
                    
                    {scan.ai_analysis && (
                      <div className="mt-4 p-4 bg-purple-900/20 border border-purple-500/30 rounded-lg">
                        <h4 className="text-purple-400 font-semibold mb-2 flex items-center">
                          <Brain className="w-4 h-4 mr-2" />
                          AI Analysis
                        </h4>
                        <div className="text-gray-300 text-sm whitespace-pre-wrap">
                          {scan.ai_analysis}
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))}
              
              {scans.length === 0 && (
                <Card className="bg-gray-800 border-gray-700">
                  <CardContent className="text-center py-8">
                    <Target className="h-12 w-12 text-gray-600 mx-auto mb-4" />
                    <div className="text-gray-400">No scans yet. Start your first scan above.</div>
                  </CardContent>
                </Card>
              )}
            </div>
          </TabsContent>

          <TabsContent value="recon">
            <Card className="bg-gray-800 border-gray-700">
              <CardContent className="text-center py-8">
                <Search className="h-12 w-12 text-gray-600 mx-auto mb-4" />
                <div className="text-gray-400">Reconnaissance modules coming soon...</div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="exploits">
            <Card className="bg-gray-800 border-gray-700">
              <CardContent className="text-center py-8">
                <Lock className="h-12 w-12 text-gray-600 mx-auto mb-4" />
                <div className="text-gray-400">Exploitation modules coming soon...</div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="reports">
            <Card className="bg-gray-800 border-gray-700">
              <CardContent className="text-center py-8">
                <FileText className="h-12 w-12 text-gray-600 mx-auto mb-4" />
                <div className="text-gray-400">Reporting system coming soon...</div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}

export default App

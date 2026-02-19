
$pythonPath = "c:\Users\jjv18\Documents\minor\AI-ids-soc-project\.venv\Scripts\python.exe"

Write-Host "--- TRIGGERING MODULE 2 (Command Detection) ---"
Write-Host "Sending HTTP POST to /api/test-cmd..."
$headers = @{ "Content-Type" = "application/json" }
$body = @{
    command = "powershell -enc JABhID0gMjAwMzs="
    source = "manual_test"
    description = "Manual trigger for Module 2 demo"
} | ConvertTo-Json
try {
    $response = Invoke-RestMethod -Uri "http://localhost:5000/api/test-cmd" -Method Post -Headers $headers -Body $body
    Write-Host "Response: $response"
} catch {
    Write-Host "Error sending Module 2 trigger: $_"
}

Write-Host "`n--- TRIGGERING MODULE 1 (Network Detection) ---"
Write-Host "Sending single UDP packet to port 9999..."
& $pythonPath -c "import socket, json; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); payload={'src_ip':'192.168.1.100','dst_ip':'192.168.1.200','src_port':12345,'dst_port':80,'proto':6,'pkt_count':5000,'byte_count':500000,'duration':1.0,'is_anomaly':1, 'reason': 'Manual Module 1 Demo Attack', 'severity': 'CRITICAL'}; s.sendto(json.dumps(payload).encode(), ('127.0.0.1', 9999)); print('UDP packet sent')"

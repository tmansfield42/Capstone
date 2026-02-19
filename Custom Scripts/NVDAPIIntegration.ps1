# Your API key
$apiKey = "80e224c5-f28d-4e1e-a9d6-3e96ef864e81"


$productName = "ftp"
$version = "1.8"

# Map product names to their correct vendor and product
$mapping = @{
    "apache" = @{vendor="apache"; product="http_server"}
    "http_server" = @{vendor="apache"; product="http_server"}
    "httpd" = @{vendor="apache"; product="http_server"}
    "apache2" = @{vendor="apache"; product="http_server"}
    "apache_http_server" = @{vendor="apache"; product="http_server"}
    "iis" = @{vendor="microsoft"; product="internet_information_services"}
    "internet_information_services" = @{vendor="microsoft"; product="internet_information_services"}
    "microsoft_iis" = @{vendor="microsoft"; product="internet_information_services"}
    "nodejs" = @{vendor="nodejs"; product="node.js"}
    "node" = @{vendor="nodejs"; product="node.js"}
    "node.js" = @{vendor="nodejs"; product="node.js"}
    "filezilla" = @{vendor="filezilla-project"; product="filezilla_server"}
    "filezilla_server" = @{vendor="filezilla-project"; product="filezilla_server"}
    "filezillaserver" = @{vendor="filezilla-project"; product="filezilla_server"}
    "jre" = @{vendor="oracle"; product="jre"}
    "java" = @{vendor="oracle"; product="jre"}
    "jdk" = @{vendor="oracle"; product="jdk"}
    "java_runtime_environment" = @{vendor="oracle"; product="jre"}
    "java_development_kit" = @{vendor="oracle"; product="jdk"}
    "openjdk" = @{vendor="openjdk"; product="openjdk"}
    "mysql" = @{vendor="oracle"; product="mysql"}
    "mysql_server" = @{vendor="oracle"; product="mysql"}
    "postgresql" = @{vendor="postgresql"; product="postgresql"}
    "postgres" = @{vendor="postgresql"; product="postgresql"}
    "nginx" = @{vendor="f5"; product="nginx"}
    "php" = @{vendor="php"; product="php"}
    "tomcat" = @{vendor="apache"; product="tomcat"}
    "apache_tomcat" = @{vendor="apache"; product="tomcat"}
    "mongodb" = @{vendor="mongodb"; product="mongodb"}
    "mongo" = @{vendor="mongodb"; product="mongodb"}
    "redis" = @{vendor="redis"; product="redis"}
    "wordpress" = @{vendor="wordpress"; product="wordpress"}
    "openssl" = @{vendor="openssl"; product="openssl"}
    "python" = @{vendor="python"; product="python"}
}


if ($mapping.ContainsKey($productName.ToLower())) {
    $vendor = $mapping[$productName.ToLower()].vendor
    $product = $mapping[$productName.ToLower()].product
} else {
    $vendor = $productName.ToLower()
    $product = $productName.ToLower()
}






# Build the CPE string
$cpeName = "cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*"

# Build the API URL
$url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=$cpeName"




# Set up headers with your API key
$headers = @{
    "apiKey" = $apikey
}

# Make the request
$response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get




($response.vulnerabilities.cve.metrics.cvssMetricV2 | ConvertTo-Json -Depth 100) | Out-String
<#
foreach ($i in ($response.vulnerabilities.cve.id | ConvertTo-Json -Depth 100) | Out-String){
($response.vulnerabilities.cve.id | ConvertTo-Json -Depth 100) 
($response.vulnerabilities.cve.metrics.cvssMetricV2.exploitabilityScore | ConvertTo-Json -Depth 100) | Out-String



}


#>

<#

# Display results
Write-Host "Found $($response.totalResults) vulnerabilities for Apache 2.4.1`n" -ForegroundColor Green

foreach ($vuln in $response.vulnerabilities) {
    $cve = $vuln.cve
    
    Write-Host "CVE ID: $($cve.id)" -ForegroundColor Yellow
    Write-Host "Description: $($cve.descriptions[0].value)"
    
    # Get CVSS score (v3.1 preferred, fallback to v2.0)
    if ($cve.metrics.cvssMetricV31) {
        $cvss = $cve.metrics.cvssMetricV31[0].cvssData
        Write-Host "CVSS v3.1 Score: $($cvss.baseScore) ($($cvss.baseSeverity))" -ForegroundColor Red
    }
    elseif ($cve.metrics.cvssMetricV2) {
        $cvss = $cve.metrics.cvssMetricV2[0].cvssData
        Write-Host "CVSS v2 Score: $($cvss.baseScore)" -ForegroundColor Red
    }
    
    Write-Host "Published: $($cve.published)"
    Write-Host "---`n"
}

#>








#Requires -Version 7.0
<#
.SYNOPSIS
    PAN-OS Info Explorer v1.0 - CLI tool to retrieve operational, security and
    troubleshooting information from Palo Alto Networks firewalls via the XML API.
.DESCRIPTION
    Interactive console menu plus non-interactive parameter mode. It reuses the
    same devices.xml file used by PanOS-CertManager so registered devices and
    encrypted API keys are shared. Supports log searches, DNS Security checks,
    packet capture listing/download, dynamic reports, system/network health,
    security policy match testing and certificate management.
    The interface is available in English (default) or Spanish, selectable from
    the main menu or with -Lang.
.PARAMETER Action
    Non-interactive action to execute. If omitted, the interactive menu opens.
.PARAMETER Lang
    Interface language: en (default) or es.
.EXAMPLE
    .\PanOS-InfoExplorer-v1.0.ps1
.EXAMPLE
    .\PanOS-InfoExplorer-v1.0.ps1 -Lang es
.EXAMPLE
    .\PanOS-InfoExplorer-v1.0.ps1 -Device FW-01 -Action traffic -Src 10.1.1.50 -Dst 8.8.8.8 -Port 443 -Last 24h -Export -Format csv
.EXAMPLE
    .\PanOS-InfoExplorer-v1.0.ps1 -Device FW-01 -Action dns -Domain evil.com -Last 7d
.NOTES
    Author: Alex Milla - alexmilla.dev
    Requires PowerShell 7+ (uses -SkipCertificateCheck).
#>
[CmdletBinding()]
param(
    [string]$Device,
    [ValidateSet(
        'traffic','threat','url','wildfire','data','decryption',
        'system','auth','userid','globalprotect','iptag','corr','gtp','external','hipmatch','config','log-system',
        'dns','dns-config','dns-subtypes','pcap-list','pcap-download','report',
        'content','ha','licenses','interfaces','routes','arp','sessions','jobs','job-detail',
        'resources','session-info','vpn-ike','vpn-ipsec','sw-status','config-saved','ntp','userid-map',
        'policy','cert-list','cert-validate','devices','test','perms','commits','config-changes','pending','config-diff','cpu','drops','o2d','flow','activity'
    )]
    [string]$Action,
    [string]$Src,
    [string]$Dst,
    [string]$Port,
    [string]$Sport,
    [string]$App,
    [string]$Domain,
    [string]$Url,
    [string]$Severity,
    [string]$Rule,
    [string]$User,
    [string]$Admin,
    [ValidateSet('all','tcp','udp','frag','resource')]
    [string]$Filter = 'all',
    [string]$Last = '24h',
    [int]$Limit = 100,
    [int]$Skip = 0,
    [int]$Interval = 5,
    [int]$Iterations = 0,
    [string]$ReportName,
    [ValidateSet('dynamic','predefined','custom')]
    [string]$ReportType = 'dynamic',
    [string]$Period = 'last-24-hrs',
    [int]$TopN = 10,
    [ValidateSet('application-pcap','threat-pcap','filters-pcap','dlp-pcap')]
    [string]$PcapCategory = 'application-pcap',
    [string]$PcapFrom,
    [string]$PcapId,
    [string]$SessionId,
    [string]$SearchTime,
    [string]$JobId,
    [string]$DlpPassword,
    [string]$FromZone,
    [string]$ToZone,
    [string]$Protocol = '6',
    [ValidateSet('table','csv','json')]
    [string]$Format = 'table',
    [string]$OutDir = '.',
    [switch]$Export,
    [switch]$Raw,
    [switch]$ListDevices,
    [switch]$NoColor,
    [ValidateSet('en','es')]
    [string]$Lang
)

# ============================================================
# GLOBAL STATE / THEME
# ============================================================
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$Global:ConfigFile   = Join-Path $scriptDir 'devices.xml'
$Global:SettingsFile = Join-Path $scriptDir 'panos-explorer.settings.json'
$Global:Devices      = @()
$Global:Interactive  = $true
$Global:OutputDir    = if ($OutDir) { $OutDir } else { '.' }
$Global:UiLang         = 'en'

$Global:Theme = @{
    Title     = 'Cyan'
    Header    = 'Yellow'
    Success   = 'Green'
    Error     = 'Red'
    Warning   = 'Magenta'
    Info      = 'White'
    Highlight = 'DarkCyan'
    Menu      = 'Gray'
    Border    = 'DarkGray'
    Device    = 'Cyan'
    Good      = 'Green'
    Bad       = 'Red'
    Caution   = 'Yellow'
    Neutral   = 'Gray'
    Muted     = 'DarkGray'
}
if ($NoColor) {
    foreach ($k in @($Global:Theme.Keys)) { $Global:Theme[$k] = 'Gray' }
}

try { [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture } catch { }

# ============================================================
# I18N - TRANSLATIONS (default: English)
# ============================================================
$Global:Strings = @{
    en = @{
        bannerTitle      = ' PAN-OS INFO EXPLORER v1.0 '
        bannerSubtitle   = 'Logs - DNS Security - PCAP - Reports - System - Certificates'
        author           = 'Author: Alex Milla - alexmilla.dev'
        pressEnter       = 'Press ENTER to continue'
        invalidOption    = 'Invalid option.'
        invalidSelection = 'Invalid selection.'
        back             = 'Back'
        noResults        = 'No results.'
        nothingToExport  = 'Nothing to export.'
        exported         = 'Exported: {0}'
        exportFailed     = 'Export failed: {0}'

        noDevices        = 'No registered devices.'
        selectDevice     = 'Select Device'
        deviceNumber     = 'Device number'
        devicesTitle     = 'Registered Devices'
        devTitle         = 'Devices'
        devList          = 'List devices'
        devAdd           = 'Add device'
        devRemove        = 'Remove device'
        devRenew         = 'Renew API key'
        devTest          = 'Test connection'
        addName          = 'Descriptive name'
        addHost          = 'Firewall IP or hostname'
        addVersion       = 'Approximate PAN-OS version (optional)'
        addAuth          = 'Select authentication [1/2]'
        addAuth1         = 'Enter API Key'
        addAuth2         = 'Generate API Key with user/password'
        addUser          = 'Admin username'
        addPass          = 'Password'
        addKeyEmpty      = 'API Key cannot be empty.'
        addHostRequired  = 'Host is required.'
        addKeyGen        = 'Generating API Key on {0} ...'
        addKeyGenOk      = 'API Key generated.'
        addKeyFail       = 'Could not obtain API Key.'
        connOk           = 'Connection OK. Hostname: {0}   PAN-OS: {1}'
        connFailWarn     = 'Could not verify connection.'
        saveAnyway       = 'Save device anyway?'
        deviceSaved      = 'Device saved.'
        removeConfirm    = "Remove '{0}' ({1})?"
        deviceRemoved    = 'Device removed.'
        keyRenewed       = "API Key renewed for '{0}'."
        connOkShort      = 'OK: {0} ({1})'
        connFailed       = 'Connection failed.'
        deviceLabel      = 'Device: {0} ({1})'
        deviceNotFound   = "Device '{0}' not found. Use -ListDevices."
        noDevInteractive = 'No devices registered. Run interactively to add one.'
        unknownAction    = 'Unknown action.'

        noResponse            = 'No response from firewall (timeout or network error).'
        couldNotParse         = 'Could not parse response: {0}'
        unknownApiError       = 'Unknown API error.'
        unknownApiErrorStatus = 'Unknown API error (status: {0}).'
        couldNotGetKey        = 'Could not get API Key: {0}'
        connectionError       = 'Connection error: {0}'
        missingApiKey         = 'Missing API key.'
        apiError              = 'API error ({0}): {1}'
        jobTimeout            = 'Timeout waiting for job {0}.'

        query            = 'Query: {0}'
        retrievingLogs   = 'Retrieving {0} logs (max {1})...'
        entriesReturned  = 'Entries returned: {0}'
        emptyQuery       = 'Empty query; add at least a time window.'
        logQueryFailed   = 'Log query failed: {0}'
        logSearchTitle   = 'Log Search'
        logTypePrompt    = 'Log type [1-7]'
        logAdvanced      = 'Advanced raw query'
        logRawType       = 'log-type (traffic/threat/url/wildfire/data/decryption)'
        logRawQuery      = 'Raw Monitor query'
        srcPrompt        = 'Source IP (Enter=any)'
        dstPrompt        = 'Destination IP (Enter=any)'
        dportPrompt      = 'Destination port (Enter=any)'
        appPrompt        = 'Application (Enter=any)'
        domainPrompt     = 'Domain/URL contains (Enter=any)'
        severityPrompt   = 'Severity [low/medium/high/critical] (Enter=any)'
        windowPrompt     = 'Window [1h/6h/24h/7d/30d or yyyy/MM/dd HH:mm:ss] (Enter=24h)'

        dnsTitle            = 'DNS Secure'
        dnsCheck            = 'DNS Security check'
        dnsWindow           = 'Window: since {0}'
        dnsDomain           = 'Domain: {0}'
        dnsSearchThreat     = 'Searching threat logs (subtype dns)...'
        dnsSearchUrl        = 'Searching URL filtering logs...'
        dnsResultHeader     = 'DNS SECURITY RESULT'
        dnsBlocked          = 'VERDICT: BLOCKED - {0} matching event(s) for {1}.'
        dnsAllowed          = 'VERDICT: ALLOWED - events found for {0} with no block action.'
        dnsNoData           = 'VERDICT: NO DATA - no DNS/URL events for {0} in the window.'
        dnsEventsCount      = 'DNS Security events in window: {0} (threat, subtype dns).'
        dnsUrlCount         = 'URL log entries in window: {0}.'
        dnsNoEvents         = 'No matching events to display.'
        dnsUrlTest          = 'URL filtering quick test (optional):'
        dnsUrlTestResult    = 'test url -> {0}'
        dnsUrlTestUnavail   = 'test url unavailable: {0}'
        dnsDomainPrompt     = 'Domain to check (Enter only to list all DNS events)'
        dnsWindowPrompt     = 'Window [1h/24h/7d/30d] (Enter=7d)'

        policyTitle       = 'Policy Match (experimental)'
        policyExpWarn     = 'This uses an operational command not documented in the API guide.'
        policySrcPrompt   = 'Source IP'
        policyDstPrompt   = 'Destination IP'
        policyPortPrompt  = 'Destination port (optional)'
        policyAppPrompt   = 'Application (optional)'
        policyProtoPrompt = 'Protocol [tcp/udp/icmp/number] (Enter=6 TCP)'
        policyNeedSrcDst  = 'Source and destination are required for a policy match.'
        policyNoResponse  = 'No response from policy-match (command may not be supported).'
        policyError       = 'Policy match error: {0}'

        pcapTitle            = 'Packet Capture / PCAP'
        pcapListApp          = 'List application PCAPs (directory)'
        pcapListAppDate      = 'List application PCAPs by date (from=yyyymmdd)'
        pcapDlApp            = 'Download application PCAP (from=yyyymmdd/filename)'
        pcapDlFilters        = 'Download filtered PCAP (filters-pcap)'
        pcapDlThreat         = 'Download threat PCAP (by pcap-id)'
        pcapDlDlp            = 'Download DLP PCAP (dlp-pcap)'
        pcapLive             = 'Live capture (experimental)'
        pcapListFailed       = 'Could not list PCAPs: {0}'
        pcapSaved            = 'PCAP saved: {0}'
        pcapDownloadFailed   = 'PCAP download failed: {0}'
        threatPcapNeedId     = 'Threat PCAP needs a pcap-id.'
        threatPcapSaved      = 'Threat PCAP saved: {0}'
        threatPcapFailed     = 'Threat PCAP download failed: {0}'
        pcapFromDatePrompt   = 'Date yyyymmdd'
        pcapFromPrompt       = 'from (yyyymmdd/filename)'
        pcapOutPrompt        = 'Output file (Enter=auto)'
        pcapPcapIdPrompt     = 'pcap-id'
        pcapSessionIdPrompt  = 'sessionid (optional)'
        pcapSearchTimePrompt = 'search-time yyyy/mm/dd hr:min:sec (optional)'
        pcapDevNamePrompt    = 'device_name (optional)'
        pcapDlpPassPrompt    = 'DLP password'
        liveWarn             = 'Live capture is EXPERIMENTAL and may not be permitted on all PAN-OS roles/versions.'
        liveSrcPrompt        = 'Source IP (optional)'
        liveDstPrompt        = 'Destination IP (optional)'
        livePortPrompt       = 'Destination port (optional)'
        liveSecPrompt        = 'Duration seconds (Enter=15)'
        liveNeedMatch        = 'Provide at least -Src, -Dst or -Port for a live capture.'
        liveSetFail          = 'Cannot set capture filter: {0}'
        liveStartFail        = 'Cannot start capture: {0}'
        liveRunning          = 'Capture running for {0} s...'
        liveDownloading      = 'Downloading captured file...'
        expConfirm           = 'This feature is experimental. Continue?'

        reportTitle        = 'Reports'
        reportFetching     = 'Fetching available {0} reports...'
        reportRunning      = "Running {0} report '{1}'..."
        reportError        = 'Report error: {0}'
        reportNamePrompt   = 'Report name'
        reportPeriodPrompt = 'Period [last-60-seconds/last-15-minutes/last-hour/last-12-hrs/last-calendar-day/last-7-days/last-30-days] (Enter=last-24-hrs)'
        reportTopnPrompt   = 'Top N (Enter=10)'

        sysTitle        = 'System / Network'
        sysReadFailed   = 'Could not read system info: {0}'
        sysHostname     = 'Hostname'
        sysModel        = 'Model'
        sysSerial       = 'Serial'
        sysVersion      = 'PAN-OS version'
        sysUptime       = 'Uptime'
        sysMgmtIp       = 'Management IP'
        sysOpMode       = 'Operational mode'
        sysMultiVsys    = 'Multi-vsys'
        contentReadFailed = 'Could not read content versions: {0}'
        cAppThreat      = 'App/Threat version'
        cAppRelease     = 'App release date'
        cAv             = 'Antivirus version'
        cThreat         = 'Threat version'
        cUrl            = 'URL filtering version'
        cWildfire       = 'WildFire version'
        cLogdb          = 'Log DB version'
        cDevCert        = 'Device certificate'
        opNoResponse    = 'No response for {0}.'
        sysInfoItem     = 'System info'
        sysContentItem  = 'Content versions'
        sysHaItem       = 'HA status'
        sysLicItem      = 'Licenses'
        sysIfItem       = 'Interfaces'
        sysRouteItem    = 'Routing table'
        sysArpItem      = 'ARP table'
        sysSessionItem  = 'Sessions (filter)'
        sysJobsItem     = 'Jobs'
        sessionSrcPrompt = 'Source IP (optional)'
        sessionDstPrompt = 'Destination IP (optional)'
        sessionAppPrompt = 'Application (optional)'

        histTitle        = 'Commit & config history'
        histCommits      = 'Commit history (jobs)'
        histChanges      = 'Config changes (audit log)'
        histPending      = 'Pending changes (candidate vs running)'
        histDiff         = 'Full diff running vs candidate'
        histAdminPrompt  = 'Filter by admin user (Enter=any)'
        histWindowPrompt = 'Window [1h/24h/7d/30d] (Enter=7d)'
        histLimitPrompt  = 'Max entries (Enter=200)'
        histNote         = 'Commit history comes from job records; config audit log retention depends on the device.'
        noCommits        = 'No commit jobs found.'
        diffFailed       = 'Could not retrieve running/candidate config.'
        diffNone         = 'No differences found (candidate equals running).'
        diffLines        = 'Diff lines: {0}'
        askExport        = 'Export these results? [Y/N]'
        exportFormatPrompt = 'Format [csv/json] (Enter=csv)'

        certTitle           = 'Certificates'
        certDashboard       = 'Certificate Dashboard - {0}'
        noCertificates      = 'No certificates found.'
        certNotFound        = 'Certificate not found.'
        certDetailTitle     = 'Certificate: {0}'
        certMenuDashboard   = 'Dashboard'
        certMenuValidate    = 'Validate all certificates'
        certMenuDetail      = 'Certificate detail'
        certMenuGenerate    = 'Generate certificate (CA or signed)'
        certMenuImport      = 'Import certificate'
        certMenuExport      = 'Export certificate'
        certMenuDelete      = 'Delete certificate'
        certNamePrompt      = 'Certificate name'
        certNewNamePrompt   = 'New certificate name'
        certCnPrompt        = 'Common Name (CN)'
        certTypePrompt      = 'Type [1/2]'
        certTypeOpts        = 'Type: [1] Self-signed CA   [2] Signed by local CA'
        certBitsPrompt      = 'RSA bits [2048/3072/4096] (Enter=2048)'
        certDigestPrompt    = 'Digest [sha256/sha384/sha512] (Enter=sha256)'
        certNoCa            = 'No CA certificates available.'
        certSelectCa        = 'Select CA number'
        certDaysPrompt      = 'Validity days (Enter=365)'
        certGenerated       = "Certificate '{0}' generated."
        certGenFailed       = 'Generation failed: {0}'
        certFilePrompt      = 'Path to file (.pem/.pfx/.p12)'
        certFormatPrompt    = 'Format [pem/pkcs12] (Enter=pem)'
        certPassPrompt      = 'Passphrase (Enter if none)'
        certNameFwPrompt    = 'Certificate name on firewall'
        certFileNotFound    = 'File not found: {0}'
        certImported        = 'Certificate imported.'
        certImportFailed    = 'Import failed: {0}'
        certOutPrompt       = 'Output file path (e.g. C:\certs\cert.pem)'
        certExported        = 'Exported to {0}'
        certExportFailed    = 'Export failed: {0}'
        certDeleteNamePrompt = 'Certificate name to delete'
        certDeleteConfirm   = "Delete '{0}'?"
        certDeleted         = "Deleted '{0}'."
        certDeleteFailed    = 'Delete failed.'
        certUnknown         = 'UNKNOWN'
        certExpired         = 'EXPIRED'
        certSoon            = 'SOON ({0} d)'
        certValid           = 'VALID ({0} d)'
        dName               = 'Name'
        dIsCA               = 'Is CA'
        dSubject            = 'Subject'
        dIssuer             = 'Issuer'
        dAlgo               = 'Algorithm'
        dKeySize            = 'Key size'
        dDigest             = 'Digest'
        dValidFrom          = 'Valid from'
        dExpires            = 'Expires'
        dSerial             = 'Serial'
        dThumbprint         = 'Thumbprint'

        noData           = 'No data to display.'
        haLocal          = 'Local'
        haPeer           = 'Peer'
        sysJobDetailItem = 'Job detail'
        sysResourcesItem = 'System resources'
        sysSessionInfoItem = 'Session info'
        sysIkeItem       = 'VPN IKE SAs'
        sysIpsecItem     = 'VPN IPsec SAs'
        sysSwItem        = 'Software status'
        sysSavedItem     = 'Saved configs'
        sysNtpItem       = 'NTP'
        sysUseridItem    = 'User-ID mappings'
        devPerms         = 'Test API permissions'
        permTitle        = 'API permissions'
        permOp           = 'Operational requests (op)'
        permConfig       = 'Configuration (config)'
        permLog          = 'Logs (log)'
        permReport       = 'Reports (report)'
        permHint         = 'If DENIED, enable the matching XML API feature in Device > Admin Roles > XML API.'
        logAggregate     = 'Aggregate summary'
        logLimitPrompt   = 'Max entries (Enter={0})'
        logDirPrompt     = 'Direction [forward/backward] (Enter=backward)'
        logAggPrompt     = 'Show aggregate summary (top app/src/dst)?'
        dnsUsingSubtype  = 'Using threat log subtype: {0}'
        dnsFallback      = 'Falling back to domain search (misc contains)...'
        dnsCfgProfiles   = 'DNS / Anti-Spyware profiles'
        dnsCfgProxy      = 'DNS Proxy configuration'
        dnsCfgRules      = 'Security rules and their profiles'
        dnsCfgContent    = 'DNS/Threat content version'
        dnsMenuCheck     = 'Check if a domain is blocked'
        dnsMenuSubtypes  = 'List available threat subtypes'
        dnsMenuConfig    = 'View DNS / Anti-Spyware configuration'
        cfgUnavailable   = 'Configuration node unavailable: {0}'
        cfgNoData        = 'No configuration data to display.'
        reportNone       = 'No report names returned.'
        histJobDetail    = 'Job detail (by job id)'
        histSaved        = 'Saved config snapshots'
        histCmdPrompt    = 'Filter by command [set/edit/delete/commit] (Enter=any)'
        histPathPrompt   = 'Filter by path contains (Enter=any)'
        histJobIdPrompt  = 'Job id'

        grpLogCore       = 'TRAFFIC / SECURITY'
        grpLogSystem     = 'SYSTEM / EVENTS'
        grpLogAdvanced   = 'ADVANCED'
        grpList          = 'LIST'
        grpDownload      = 'DOWNLOAD'
        grpLive          = 'ADVANCED'
        grpInfo          = 'INFORMATION'
        grpAdvanced      = 'ADVANCED'
        grpAnalysis      = 'ANALYSIS'
        grpTools         = 'TOOLS'
        grpSystem        = 'SYSTEM'
        reportList       = 'List available reports'
        userPrompt       = 'User (Enter=any)'
        cfgAdminPrompt   = 'Admin user (Enter=any)'
        cfgCmdPrompt     = 'Command [set/edit/delete/commit] (Enter=any)'
        cfgPathPrompt    = 'Path contains (Enter=any)'
        cfgObject        = 'Object'
        dnsCfgUrl        = 'URL filtering profiles'

        cpuTitle     = 'CPU / Cores monitor'
        cpuUptime    = 'Uptime'
        cpuLoad      = 'Load (1/5/15)'
        cpuMgmt      = 'MANAGEMENT CPU'
        cpuMem       = 'MEMORY'
        cpuSwap      = 'SWAP'
        cpuPerCore   = 'DATAPLANE - per core (last sample)'
        cpuGroups    = 'DATAPLANE - pipeline stages'
        cpuResources = 'RESOURCE UTILIZATION'
        cpuTopProc   = 'TOP PROCESSES (CPU)'
        cpuKeys      = '[Q] quit  [P] pause  [R] refresh  [+/-] interval  [D] detail  [G] core map  [H] 1s/1m'
        cpuRefresh   = 'refresh {0}s'
        cpuPaused    = 'PAUSED'
        cpuAvailable = 'available'
        cpuNoData    = 'No CPU data available.'
        cpuReserved  = 'reserved'

        hintPermFeature  = 'Required XML API permission: {0}. Enable it in Device > Admin Roles > XML API.'
        hintPermGeneric  = 'Operation not authorized. Check the XML API permissions of your admin role (Device > Admin Roles > XML API).'
        hintPermDebug    = 'This needs the Command Line role (Superuser) and is usually not exposed via XML API.'
        liveUnsupported  = 'Live capture is not available via the XML API (the "debug" node is rejected and/or requires Command Line/Superuser). Use the CLI/SSH or the GUI packet capture, then download the PCAP here with options [3]/[4].'
        protoInvalid     = "Invalid protocol '{0}'; using TCP (6)."
        cpuSaturated     = '{0} core(s) over 80%'
        cpuRmError       = 'No per-core data: resource monitor returned: {0}'
        cpuRmEmpty       = 'No per-core data (resource monitor returned nothing; try sub-mode second/minute, or the command path differs).'
        dropsTitle       = 'Packet drops / counters'
        grpDrops         = 'DROPS'
        dropsAll         = 'All drops (severity=drop)'
        dropsTcp         = 'TCP drops'
        dropsUdp         = 'UDP drops'
        dropsFrag        = 'Fragmentation drops'
        dropsResource    = 'Resource drops (buffers/mem)'
        ifCountersTitle  = 'Interface counters'
        dropsTotal       = 'Drop counters returned: {0} (showing non-zero)'
        dropsNone        = 'No drops (all counters are zero).'

        cpuCoreTask      = 'CORE -> FUNCTION (task map)'
        ifcSummary       = '{0} interfaces; {1} with drops; total errors {2}, drops {3}'
        dropsSummary     = '{0} counter(s) with drops; total {1} drops'
        dropDescFrag     = 'IP fragmentation discarded'
        dropDescOffload  = 'Offload / fixed-function drops'
        dropDescTcp      = 'TCP session drops'
        dropDescUdp      = 'UDP drops'
        dropDescDns      = 'DNS Security / Proxy drops'
        dropDescResource = 'Out of resources/buffers (possible microburst)'
        dropDescPolicy   = 'Denied by policy'
        dropDescDecrypt  = 'Decryption / SSL drops'
        dropDescSession  = 'Session limit / teardown drops'
        dropDescIp       = 'IP / ICMP validation drops'
        dropDescOther    = 'Other drops'

        dnsMenuO2D       = 'Origin -> destination test'
        o2dSrcPrompt     = 'Source IP (Enter=any)'
        o2dDstPrompt     = 'Destination domain or IP'
        o2dDstReq        = 'Destination is required.'
        o2dResultHeader  = 'ORIGIN -> DESTINATION TEST'
        o2dLine          = 'Source {0}   Destination {1}   Port {2}   App {3}'
        o2dVerdictBLOCKED = 'VERDICT: BLOCKED for {0}'
        o2dVerdictALLOWED = 'VERDICT: ALLOWED for {0}'
        o2dVerdictUNKNOWN = 'VERDICT: NO DATA for {0}'
        o2dPolicy        = 'POLICY (policy match)'
        o2dTraffic       = 'TRAFFIC LOGS'
        o2dDns           = 'DNS SECURITY'
        o2dUrl           = 'URL FILTERING'
        o2dEvents        = '{0} events'
        o2dBlocks        = '{0} blocks'
        o2dNeedSrc       = 'provide source IP to test policy'
        o2dNoDstIp       = 'no destination IP (domain only)'

        flowTitle        = 'FLOW INVESTIGATION (origin -> destination)'
        flowPath         = 'PATH'
        flowHopOrigin    = 'Origin'
        flowHopPolicy    = 'Policy'
        flowHopNat       = 'NAT'
        flowHopRoute     = 'Route'
        flowHopDest      = 'Destination'
        flowHopResolve   = 'DNS resolution'
        flowHopUrl       = 'URL category'
        flowPolicySec    = 'POLICY (policy match)'
        flowSessionsSec  = 'CURRENT SESSIONS'
        flowTrafficSec   = 'TRAFFIC LOGS'
        flowUrlSec       = 'URL / DNS'
        flowDropsSec     = 'DROPS (global, non-zero)'
        flowNa           = 'n/a'
        o2dNeedSrcDst    = 'Source and destination are required.'

        flowNotResolved  = 'Domain {0} not resolved; showing only logs containing the domain.'
        flowDnsDiag      = 'DNS DIAGNOSIS (why it may not resolve)'
        flowDnsPing      = 'Firewall ping (mgmt DNS)'
        flowDnsServers   = 'Firewall DNS servers'
        flowDnsProxy     = 'DNS proxy stats'
        flowDnsThreat    = 'DNS security events'
        flowDnsBugHint   = 'Known cause: a trailing dot in the system domain name can break FQDN resolution (PAN-193484; fixed in 10.1.11/10.2.3+).'

        flowHopConn      = 'Connectivity'
        flowObservedFlows = 'OBSERVED FLOWS (from traffic logs)'
        flowPolicyPerFlow = 'POLICY PER OBSERVED FLOW'
        flowConnProbes   = 'CONNECTIVITY (ping/traceroute from firewall)'
        flowPing         = 'ping'
        flowTraceroute   = 'traceroute'
        flowAskPort      = 'No observed flows. Port to test policy (1-65535, Enter=skip)'
        policyPortRequired = 'Policy match needs a destination port (1-65535); skipping.'

        flowDropsFilter   = 'Drops filter [all/tcp/udp/frag/resource] (Enter=all)'

        userActTitle     = 'USER ACTIVITY (live, by source IP)'
        userActKeys      = '[Q] quit  [P] pause  [R] refresh  [+/-] interval'
        userNeedSrc      = 'Source IP is required.'
        userWindow       = 'Window'
        userIpPrompt     = 'Source IP (user) to monitor'
        userWindowPrompt = 'Window [1h/6h/24h] (Enter=1h)'
        userSecRules     = 'POLICIES / RULES'
        userSecDests     = 'DESTINATIONS'
        userSecBlocks    = 'BLOCKED'
        userSecApps      = 'APPLICATIONS'
        userSecCats      = 'URL CATEGORIES'
        userSecSessions  = 'LIVE SESSIONS'
        userSecThreats   = 'THREATS'
        menuUserAct      = 'User activity (live, by IP)'

        userDirOut       = 'Out'
        userDirIn        = 'In'
        userDirLocal     = 'Local'

        menuLogSearch = 'Log search'
        menuDns       = 'DNS Secure (domain blocked?)'
        menuPcap      = 'Packet capture / PCAP (list & download)'
        menuReports   = 'Dynamic reports'
        menuSystem    = 'System, health & network'
        menuPolicy    = 'Flow / policy investigation'
        menuHistory   = 'Commit / config history'
        menuCert      = 'Certificates'
        menuDevices   = 'Devices'
        menuLang      = 'Language / Idioma'
        menuExit      = 'Exit'
        statusBar     = '[Devices: {0}]  [Lang: {1}]  [Date: {2}]'
        selectOption  = 'Select option'
        goodbye       = 'Goodbye.'

        langTitle   = 'Language / Idioma'
        langSelect  = 'Select language [1/2]'
        langEnglish = 'English'
        langSpanish = 'Espanol'
        langSet     = 'Language set to English.'
    }
    es = @{
        bannerTitle      = ' PAN-OS INFO EXPLORER v1.0 '
        bannerSubtitle   = 'Logs - DNS Secure - PCAP - Informes - Sistema - Certificados'
        author           = 'Autor: Alex Milla - alexmilla.dev'
        pressEnter       = 'Pulse ENTER para continuar'
        invalidOption    = 'Opcion no valida.'
        invalidSelection = 'Seleccion no valida.'
        back             = 'Volver'
        noResults        = 'Sin resultados.'
        nothingToExport  = 'Nada que exportar.'
        exported         = 'Exportado: {0}'
        exportFailed     = 'Fallo al exportar: {0}'

        noDevices        = 'No hay dispositivos registrados.'
        selectDevice     = 'Seleccionar dispositivo'
        deviceNumber     = 'Numero de dispositivo'
        devicesTitle     = 'Dispositivos registrados'
        devTitle         = 'Dispositivos'
        devList          = 'Listar dispositivos'
        devAdd           = 'Anadir dispositivo'
        devRemove        = 'Eliminar dispositivo'
        devRenew         = 'Renovar API key'
        devTest          = 'Probar conexion'
        addName          = 'Nombre descriptivo'
        addHost          = 'IP o hostname del firewall'
        addVersion       = 'Version PAN-OS aproximada (opcional)'
        addAuth          = 'Seleccione autenticacion [1/2]'
        addAuth1         = 'Introducir API Key'
        addAuth2         = 'Generar API Key con usuario/contrasena'
        addUser          = 'Usuario administrador'
        addPass          = 'Contrasena'
        addKeyEmpty      = 'La API Key no puede estar vacia.'
        addHostRequired  = 'El host es obligatorio.'
        addKeyGen        = 'Generando API Key en {0} ...'
        addKeyGenOk      = 'API Key generada.'
        addKeyFail       = 'No se pudo obtener la API Key.'
        connOk           = 'Conexion OK. Hostname: {0}   PAN-OS: {1}'
        connFailWarn     = 'No se pudo verificar la conexion.'
        saveAnyway       = 'Guardar el dispositivo igualmente?'
        deviceSaved      = 'Dispositivo guardado.'
        removeConfirm    = "Eliminar '{0}' ({1})?"
        deviceRemoved    = 'Dispositivo eliminado.'
        keyRenewed       = "API Key renovada para '{0}'."
        connOkShort      = 'OK: {0} ({1})'
        connFailed       = 'Conexion fallida.'
        deviceLabel      = 'Dispositivo: {0} ({1})'
        deviceNotFound   = "Dispositivo '{0}' no encontrado. Use -ListDevices."
        noDevInteractive = 'No hay dispositivos registrados. Ejecute en modo interactivo para anadir uno.'
        unknownAction    = 'Accion desconocida.'

        noResponse            = 'Sin respuesta del firewall (timeout o error de red).'
        couldNotParse         = 'No se pudo interpretar la respuesta: {0}'
        unknownApiError       = 'Error de API desconocido.'
        unknownApiErrorStatus = 'Error de API desconocido (estado: {0}).'
        couldNotGetKey        = 'No se pudo obtener la API Key: {0}'
        connectionError       = 'Error de conexion: {0}'
        missingApiKey         = 'Falta la API key.'
        apiError              = 'Error de API ({0}): {1}'
        jobTimeout            = 'Timeout esperando el job {0}.'

        query            = 'Consulta: {0}'
        retrievingLogs   = 'Recuperando logs de {0} (max {1})...'
        entriesReturned  = 'Entradas devueltas: {0}'
        emptyQuery       = 'Consulta vacia; incluya al menos una ventana temporal.'
        logQueryFailed   = 'Fallo en la consulta de logs: {0}'
        logSearchTitle   = 'Busqueda en logs'
        logTypePrompt    = 'Tipo de log [1-7]'
        logAdvanced      = 'Consulta avanzada (raw)'
        logRawType       = 'log-type (traffic/threat/url/wildfire/data/decryption)'
        logRawQuery      = 'Consulta raw de Monitor'
        srcPrompt        = 'IP origen (Enter=cualquiera)'
        dstPrompt        = 'IP destino (Enter=cualquiera)'
        dportPrompt      = 'Puerto destino (Enter=cualquiera)'
        appPrompt        = 'Aplicacion (Enter=cualquiera)'
        domainPrompt     = 'El dominio/URL contiene (Enter=cualquiera)'
        severityPrompt   = 'Severidad [low/medium/high/critical] (Enter=cualquiera)'
        windowPrompt     = 'Ventana [1h/6h/24h/7d/30d o yyyy/MM/dd HH:mm:ss] (Enter=24h)'

        dnsTitle          = 'DNS Secure'
        dnsCheck          = 'Comprobacion DNS Security'
        dnsWindow         = 'Ventana: desde {0}'
        dnsDomain         = 'Dominio: {0}'
        dnsSearchThreat   = 'Buscando en threat logs (subtype dns)...'
        dnsSearchUrl      = 'Buscando en logs de filtrado URL...'
        dnsResultHeader   = 'RESULTADO DNS SECURITY'
        dnsBlocked        = 'VEREDICTO: BLOQUEADO - {0} evento(s) para {1}.'
        dnsAllowed        = 'VEREDICTO: PERMITIDO - hay eventos para {0} sin accion de bloqueo.'
        dnsNoData         = 'VEREDICTO: SIN DATOS - sin eventos DNS/URL para {0} en la ventana.'
        dnsEventsCount    = 'Eventos DNS Security en la ventana: {0} (threat, subtype dns).'
        dnsUrlCount       = 'Entradas de log URL en la ventana: {0}.'
        dnsNoEvents       = 'No hay eventos que mostrar.'
        dnsUrlTest        = 'Test rapido de filtrado URL (opcional):'
        dnsUrlTestResult  = 'test url -> {0}'
        dnsUrlTestUnavail = 'test url no disponible: {0}'
        dnsDomainPrompt   = 'Dominio a comprobar (Enter para listar todos los eventos DNS)'
        dnsWindowPrompt   = 'Ventana [1h/24h/7d/30d] (Enter=7d)'

        policyTitle       = 'Test de politica (experimental)'
        policyExpWarn     = 'Usa un comando operacional no documentado en la guia API.'
        policySrcPrompt   = 'IP origen'
        policyDstPrompt   = 'IP destino'
        policyPortPrompt  = 'Puerto destino (opcional)'
        policyAppPrompt   = 'Aplicacion (opcional)'
        policyProtoPrompt = 'Protocolo [tcp/udp/icmp/numero] (Enter=6 TCP)'
        policyNeedSrcDst  = 'Origen y destino son obligatorios para el test de politica.'
        policyNoResponse  = 'Sin respuesta de policy-match (puede que el comando no este soportado).'
        policyError       = 'Error de policy match: {0}'

        pcapTitle            = 'Captura de paquetes / PCAP'
        pcapListApp          = 'Listar PCAPs de aplicacion (directorio)'
        pcapListAppDate      = 'Listar PCAPs por fecha (from=yyyymmdd)'
        pcapDlApp            = 'Descargar PCAP de aplicacion (from=yyyymmdd/filename)'
        pcapDlFilters        = 'Descargar PCAP filtrado (filters-pcap)'
        pcapDlThreat         = 'Descargar PCAP de amenaza (por pcap-id)'
        pcapDlDlp            = 'Descargar PCAP DLP (dlp-pcap)'
        pcapLive             = 'Captura en vivo (experimental)'
        pcapListFailed       = 'No se pudieron listar los PCAPs: {0}'
        pcapSaved            = 'PCAP guardado: {0}'
        pcapDownloadFailed   = 'Fallo al descargar PCAP: {0}'
        threatPcapNeedId     = 'El PCAP de amenaza requiere un pcap-id.'
        threatPcapSaved      = 'PCAP de amenaza guardado: {0}'
        threatPcapFailed     = 'Fallo al descargar el PCAP de amenaza: {0}'
        pcapFromDatePrompt   = 'Fecha yyyymmdd'
        pcapFromPrompt       = 'from (yyyymmdd/filename)'
        pcapOutPrompt        = 'Fichero de salida (Enter=auto)'
        pcapPcapIdPrompt     = 'pcap-id'
        pcapSessionIdPrompt  = 'sessionid (opcional)'
        pcapSearchTimePrompt = 'search-time yyyy/mm/dd hr:min:sec (opcional)'
        pcapDevNamePrompt    = 'device_name (opcional)'
        pcapDlpPassPrompt    = 'Contrasena DLP'
        liveWarn             = 'La captura en vivo es EXPERIMENTAL y puede no estar permitida segun rol/version de PAN-OS.'
        liveSrcPrompt        = 'IP origen (opcional)'
        liveDstPrompt        = 'IP destino (opcional)'
        livePortPrompt       = 'Puerto destino (opcional)'
        liveSecPrompt        = 'Duracion en segundos (Enter=15)'
        liveNeedMatch        = 'Indique al menos -Src, -Dst o -Port para la captura en vivo.'
        liveSetFail          = 'No se pudo establecer el filtro de captura: {0}'
        liveStartFail        = 'No se pudo iniciar la captura: {0}'
        liveRunning          = 'Captura en curso durante {0} s...'
        liveDownloading      = 'Descargando el fichero capturado...'
        expConfirm           = 'Esta funcion es experimental. Continuar?'

        reportTitle        = 'Informes'
        reportFetching     = 'Obteniendo informes {0} disponibles...'
        reportRunning      = "Ejecutando informe {0} '{1}'..."
        reportError        = 'Error de informe: {0}'
        reportNamePrompt   = 'Nombre del informe'
        reportPeriodPrompt = 'Periodo [last-60-seconds/last-15-minutes/last-hour/last-12-hrs/last-calendar-day/last-7-days/last-30-days] (Enter=last-24-hrs)'
        reportTopnPrompt   = 'Top N (Enter=10)'

        sysTitle        = 'Sistema / Red'
        sysReadFailed   = 'No se pudo leer la info del sistema: {0}'
        sysHostname     = 'Hostname'
        sysModel        = 'Modelo'
        sysSerial       = 'Serie'
        sysVersion      = 'Version PAN-OS'
        sysUptime       = 'Uptime'
        sysMgmtIp       = 'IP de gestion'
        sysOpMode       = 'Modo operacional'
        sysMultiVsys    = 'Multi-vsys'
        contentReadFailed = 'No se pudieron leer las versiones de contenido: {0}'
        cAppThreat      = 'Version App/Threat'
        cAppRelease     = 'Fecha de publicacion App'
        cAv             = 'Version Antivirus'
        cThreat         = 'Version Threats'
        cUrl            = 'Version URL filtering'
        cWildfire       = 'Version WildFire'
        cLogdb          = 'Version Log DB'
        cDevCert        = 'Certificado del dispositivo'
        opNoResponse    = 'Sin respuesta para {0}.'
        sysInfoItem     = 'Info del sistema'
        sysContentItem  = 'Versiones de contenido'
        sysHaItem       = 'Estado HA'
        sysLicItem      = 'Licencias'
        sysIfItem       = 'Interfaces'
        sysRouteItem    = 'Tabla de rutas'
        sysArpItem      = 'Tabla ARP'
        sysSessionItem  = 'Sesiones (filtro)'
        sysJobsItem     = 'Jobs'
        sessionSrcPrompt = 'IP origen (opcional)'
        sessionDstPrompt = 'IP destino (opcional)'
        sessionAppPrompt = 'Aplicacion (opcional)'

        histTitle        = 'Historial de commits y configuracion'
        histCommits      = 'Historial de commits (jobs)'
        histChanges      = 'Cambios de configuracion (log de auditoria)'
        histPending      = 'Cambios pendientes (candidata vs activa)'
        histDiff         = 'Diff completo activa vs candidata'
        histAdminPrompt  = 'Filtrar por usuario admin (Enter=cualquiera)'
        histWindowPrompt = 'Ventana [1h/24h/7d/30d] (Enter=7d)'
        histLimitPrompt  = 'Maximo de entradas (Enter=200)'
        histNote         = 'El historial de commits proviene de los jobs; la retencion del log de auditoria depende del equipo.'
        noCommits        = 'No se encontraron jobs de commit.'
        diffFailed       = 'No se pudo obtener la config activa/candidata.'
        diffNone         = 'Sin diferencias (la candidata es igual a la activa).'
        diffLines        = 'Lineas de diff: {0}'
        askExport        = 'Exportar estos resultados? [Y/N]'
        exportFormatPrompt = 'Formato [csv/json] (Enter=csv)'

        certTitle           = 'Certificados'
        certDashboard       = 'Panel de certificados - {0}'
        noCertificates      = 'No se encontraron certificados.'
        certNotFound        = 'Certificado no encontrado.'
        certDetailTitle     = 'Certificado: {0}'
        certMenuDashboard   = 'Panel'
        certMenuValidate    = 'Validar todos los certificados'
        certMenuDetail      = 'Detalle del certificado'
        certMenuGenerate    = 'Generar certificado (CA o firmado)'
        certMenuImport      = 'Importar certificado'
        certMenuExport      = 'Exportar certificado'
        certMenuDelete      = 'Eliminar certificado'
        certNamePrompt      = 'Nombre del certificado'
        certNewNamePrompt   = 'Nombre del nuevo certificado'
        certCnPrompt        = 'Common Name (CN)'
        certTypePrompt      = 'Tipo [1/2]'
        certTypeOpts        = 'Tipo: [1] CA autofirmado   [2] Firmado por CA local'
        certBitsPrompt      = 'Bits RSA [2048/3072/4096] (Enter=2048)'
        certDigestPrompt    = 'Digest [sha256/sha384/sha512] (Enter=sha256)'
        certNoCa            = 'No hay certificados CA disponibles.'
        certSelectCa        = 'Seleccione el numero de CA'
        certDaysPrompt      = 'Dias de validez (Enter=365)'
        certGenerated       = "Certificado '{0}' generado."
        certGenFailed       = 'Fallo al generar: {0}'
        certFilePrompt      = 'Ruta al fichero (.pem/.pfx/.p12)'
        certFormatPrompt    = 'Formato [pem/pkcs12] (Enter=pem)'
        certPassPrompt      = 'Passphrase (Enter si no hay)'
        certNameFwPrompt    = 'Nombre del certificado en el firewall'
        certFileNotFound    = 'Fichero no encontrado: {0}'
        certImported        = 'Certificado importado.'
        certImportFailed    = 'Fallo al importar: {0}'
        certOutPrompt       = 'Ruta del fichero de salida (ej. C:\certs\cert.pem)'
        certExported        = 'Exportado a {0}'
        certExportFailed    = 'Fallo al exportar: {0}'
        certDeleteNamePrompt = 'Nombre del certificado a eliminar'
        certDeleteConfirm   = "Eliminar '{0}'?"
        certDeleted         = "Eliminado '{0}'."
        certDeleteFailed    = 'Fallo al eliminar.'
        certUnknown         = 'DESCONOCIDO'
        certExpired         = 'CADUCADO'
        certSoon            = 'PROXIMO ({0} d)'
        certValid           = 'VALIDO ({0} d)'
        dName               = 'Nombre'
        dIsCA               = 'Es CA'
        dSubject            = 'Subject'
        dIssuer             = 'Issuer'
        dAlgo               = 'Algoritmo'
        dKeySize            = 'Tamano de clave'
        dDigest             = 'Digest'
        dValidFrom          = 'Valido desde'
        dExpires            = 'Caduca'
        dSerial             = 'Numero de serie'
        dThumbprint         = 'Thumbprint'

        noData           = 'No hay datos que mostrar.'
        haLocal          = 'Local'
        haPeer           = 'Peer'
        sysJobDetailItem = 'Detalle de job'
        sysResourcesItem = 'Recursos del sistema'
        sysSessionInfoItem = 'Info de sesiones'
        sysIkeItem       = 'SAs IKE VPN'
        sysIpsecItem     = 'SAs IPsec VPN'
        sysSwItem        = 'Estado del software'
        sysSavedItem     = 'Configs guardadas'
        sysNtpItem       = 'NTP'
        sysUseridItem    = 'Mapeos User-ID'
        devPerms         = 'Probar permisos API'
        permTitle        = 'Permisos de la API'
        permOp           = 'Peticiones operacionales (op)'
        permConfig       = 'Configuracion (config)'
        permLog          = 'Logs (log)'
        permReport       = 'Informes (report)'
        permHint         = 'Si aparece DENEGADO, habilite la funcion XML API correspondiente en Device > Admin Roles > XML API.'
        logAggregate     = 'Resumen agregado'
        logLimitPrompt   = 'Maximo de entradas (Enter={0})'
        logDirPrompt     = 'Direccion [forward/backward] (Enter=backward)'
        logAggPrompt     = 'Mostrar resumen agregado (top app/src/dst)?'
        dnsUsingSubtype  = 'Usando subtype del threat log: {0}'
        dnsFallback      = 'Cambiando a busqueda por dominio (misc contains)...'
        dnsCfgProfiles   = 'Perfiles DNS / Anti-Spyware'
        dnsCfgProxy      = 'Configuracion de DNS Proxy'
        dnsCfgRules      = 'Reglas de seguridad y sus perfiles'
        dnsCfgContent    = 'Version de contenido DNS/Threat'
        dnsMenuCheck     = 'Comprobar si un dominio esta bloqueado'
        dnsMenuSubtypes  = 'Listar subtypes de threat disponibles'
        dnsMenuConfig    = 'Ver configuracion DNS / Anti-Spyware'
        cfgUnavailable   = 'Nodo de configuracion no disponible: {0}'
        cfgNoData        = 'No hay datos de configuracion que mostrar.'
        reportNone       = 'No se devolvieron nombres de informes.'
        histJobDetail    = 'Detalle de job (por id)'
        histSaved        = 'Snapshots de config guardadas'
        histCmdPrompt    = 'Filtrar por comando [set/edit/delete/commit] (Enter=cualquiera)'
        histPathPrompt   = 'Filtrar por path contiene (Enter=cualquiera)'
        histJobIdPrompt  = 'Id del job'

        grpLogCore       = 'TRAFICO / SEGURIDAD'
        grpLogSystem     = 'SISTEMA / EVENTOS'
        grpLogAdvanced   = 'AVANZADO'
        grpList          = 'LISTAR'
        grpDownload      = 'DESCARGAR'
        grpLive          = 'AVANZADO'
        grpInfo          = 'INFORMACION'
        grpAdvanced      = 'AVANZADO'
        grpAnalysis      = 'ANALISIS'
        grpTools         = 'HERRAMIENTAS'
        grpSystem        = 'SISTEMA'
        reportList       = 'Listar informes disponibles'
        userPrompt       = 'Usuario (Enter=cualquiera)'
        cfgAdminPrompt   = 'Usuario admin (Enter=cualquiera)'
        cfgCmdPrompt     = 'Comando [set/edit/delete/commit] (Enter=cualquiera)'
        cfgPathPrompt    = 'El path contiene (Enter=cualquiera)'
        cfgObject        = 'Objeto'
        dnsCfgUrl        = 'Perfiles de filtrado URL'

        cpuTitle     = 'Monitor CPU / Cores'
        cpuUptime    = 'Uptime'
        cpuLoad      = 'Carga (1/5/15)'
        cpuMgmt      = 'CPU GESTION'
        cpuMem       = 'MEMORIA'
        cpuSwap      = 'SWAP'
        cpuPerCore   = 'DATAPLANE - por core (ultima muestra)'
        cpuGroups    = 'DATAPLANE - etapas del pipeline'
        cpuResources = 'UTILIZACION DE RECURSOS'
        cpuTopProc   = 'TOP PROCESOS (CPU)'
        cpuKeys      = '[Q] salir  [P] pausa  [R] refrescar  [+/-] intervalo  [D] detalle  [G] mapa core  [H] 1s/1m'
        cpuRefresh   = 'refresco {0}s'
        cpuPaused    = 'EN PAUSA'
        cpuAvailable = 'disponible'
        cpuNoData    = 'No hay datos de CPU disponibles.'
        cpuReserved  = 'reservado'

        hintPermFeature  = 'Permiso XML API requerido: {0}. Activalo en Device > Admin Roles > XML API.'
        hintPermGeneric  = 'Operacion no autorizada. Revisa los permisos XML API del rol (Device > Admin Roles > XML API).'
        hintPermDebug    = 'Requiere el rol Command Line (Superuser) y normalmente no se expone por XML API.'
        liveUnsupported  = 'La captura en vivo no esta disponible por XML API (el nodo "debug" se rechaza y/o requiere Command Line/Superuser). Usa la CLI/SSH o la captura de la GUI y descarga el PCAP aqui con las opciones [3]/[4].'
        protoInvalid     = "Protocolo invalido '{0}'; se usa TCP (6)."
        cpuSaturated     = '{0} core(s) por encima del 80%'
        cpuRmError       = 'Sin datos por core: el resource monitor devolvio: {0}'
        cpuRmEmpty       = 'Sin datos por core (el resource monitor no devolvio nada; prueba el submodo second/minute, o el path difiere).'
        dropsTitle       = 'Drops / contadores de paquetes'
        grpDrops         = 'DROPS'
        dropsAll         = 'Todos los drops (severity=drop)'
        dropsTcp         = 'Drops TCP'
        dropsUdp         = 'Drops UDP'
        dropsFrag        = 'Drops de fragmentacion'
        dropsResource    = 'Drops por recursos (buffers/mem)'
        ifCountersTitle  = 'Contadores de interfaz'
        dropsTotal       = 'Contadores de drop devueltos: {0} (se muestran los distintos de cero)'
        dropsNone        = 'Sin drops (todos los contadores a cero).'

        cpuCoreTask      = 'CORE -> FUNCION (mapa de tareas)'
        ifcSummary       = '{0} interfaces; {1} con drops; errores totales {2}, drops {3}'
        dropsSummary     = '{0} contador(es) con drops; total {1} drops'
        dropDescFrag     = 'Fragmentacion IP descartada'
        dropDescOffload  = 'Drops de offload / funcion fija'
        dropDescTcp      = 'Drops de sesion TCP'
        dropDescUdp      = 'Drops UDP'
        dropDescDns      = 'Drops de DNS Security / Proxy'
        dropDescResource = 'Sin recursos/buffers (posible microburst)'
        dropDescPolicy   = 'Denegado por politica'
        dropDescDecrypt  = 'Drops de descifrado / SSL'
        dropDescSession  = 'Drops por limite/cierre de sesion'
        dropDescIp       = 'Drops de validacion IP / ICMP'
        dropDescOther    = 'Otros drops'

        dnsMenuO2D       = 'Prueba origen -> destino'
        o2dSrcPrompt     = 'IP origen (Enter=cualquiera)'
        o2dDstPrompt     = 'Destino (dominio o IP)'
        o2dDstReq        = 'El destino es obligatorio.'
        o2dResultHeader  = 'PRUEBA ORIGEN -> DESTINO'
        o2dLine          = 'Origen {0}   Destino {1}   Puerto {2}   App {3}'
        o2dVerdictBLOCKED = 'VEREDICTO: BLOQUEADO para {0}'
        o2dVerdictALLOWED = 'VEREDICTO: PERMITIDO para {0}'
        o2dVerdictUNKNOWN = 'VEREDICTO: SIN DATOS para {0}'
        o2dPolicy        = 'POLITICA (policy match)'
        o2dTraffic       = 'TRAFFIC LOGS'
        o2dDns           = 'DNS SECURITY'
        o2dUrl           = 'URL FILTERING'
        o2dEvents        = '{0} eventos'
        o2dBlocks        = '{0} bloqueos'
        o2dNeedSrc       = 'indica IP origen para probar politica'
        o2dNoDstIp       = 'sin IP destino (solo dominio)'

        flowTitle        = 'INVESTIGACION DE FLUJO (origen -> destino)'
        flowPath         = 'CAMINO'
        flowHopOrigin    = 'Origen'
        flowHopPolicy    = 'Politica'
        flowHopNat       = 'NAT'
        flowHopRoute     = 'Ruta'
        flowHopDest      = 'Destino'
        flowHopResolve   = 'Resolucion DNS'
        flowHopUrl       = 'Categoria URL'
        flowPolicySec    = 'POLITICA (policy match)'
        flowSessionsSec  = 'SESIONES ACTUALES'
        flowTrafficSec   = 'TRAFFIC LOGS'
        flowUrlSec       = 'URL / DNS'
        flowDropsSec     = 'DROPS (globales, no cero)'
        flowNa           = 'n/d'
        o2dNeedSrcDst    = 'Origen y destino son obligatorios.'

        flowNotResolved  = 'El dominio {0} no se ha resuelto; se muestran solo los logs que contienen el dominio.'
        flowDnsDiag      = 'DIAGNOSTICO DNS (por que puede no resolver)'
        flowDnsPing      = 'Ping del firewall (DNS de gestion)'
        flowDnsServers   = 'Servidores DNS del firewall'
        flowDnsProxy     = 'Estadisticas DNS proxy'
        flowDnsThreat    = 'Eventos DNS security'
        flowDnsBugHint   = 'Causa conocida: un punto final en el dominio del sistema puede romper la resolucion de FQDN (PAN-193484; corregido en 10.1.11/10.2.3+).'

        flowHopConn      = 'Conectividad'
        flowObservedFlows = 'FLUJOS OBSERVADOS (de traffic logs)'
        flowPolicyPerFlow = 'POLITICA POR FLUJO OBSERVADO'
        flowConnProbes   = 'CONECTIVIDAD (ping/traceroute desde el firewall)'
        flowPing         = 'ping'
        flowTraceroute   = 'traceroute'
        flowAskPort      = 'Sin flujos observados. Puerto a probar (1-65535, Enter=omitir)'
        policyPortRequired = 'El policy match necesita puerto destino (1-65535); se omite.'

        flowDropsFilter   = 'Filtro de drops [all/tcp/udp/frag/resource] (Enter=all)'

        userActTitle     = 'ACTIVIDAD DE USUARIO (en vivo, por IP origen)'
        userActKeys      = '[Q] salir  [P] pausa  [R] refrescar  [+/-] intervalo'
        userNeedSrc      = 'La IP origen es obligatoria.'
        userWindow       = 'Ventana'
        userIpPrompt     = 'IP origen (usuario) a monitorizar'
        userWindowPrompt = 'Ventana [1h/6h/24h] (Enter=1h)'
        userSecRules     = 'POLITICAS / REGLAS'
        userSecDests     = 'DESTINOS'
        userSecBlocks    = 'BLOQUEOS'
        userSecApps      = 'APLICACIONES'
        userSecCats      = 'CATEGORIAS URL'
        userSecSessions  = 'SESIONES EN VIVO'
        userSecThreats   = 'AMENAZAS'
        menuUserAct      = 'Actividad de usuario (en vivo, por IP)'

        userDirOut       = 'Sal'
        userDirIn        = 'Ent'
        userDirLocal     = 'Local'

        menuLogSearch = 'Busqueda en logs'
        menuDns       = 'DNS Secure (dominio bloqueado?)'
        menuPcap      = 'Captura de paquetes / PCAP (listar y descargar)'
        menuReports   = 'Informes dinamicos'
        menuSystem    = 'Sistema, salud y red'
        menuPolicy    = 'Investigacion de flujo / politica'
        menuHistory   = 'Historial de commits / config'
        menuCert      = 'Certificados'
        menuDevices   = 'Dispositivos'
        menuLang      = 'Language / Idioma'
        menuExit      = 'Salir'
        statusBar     = '[Dispositivos: {0}]  [Idioma: {1}]  [Fecha: {2}]'
        selectOption  = 'Seleccione opcion'
        goodbye       = 'Hasta luego.'

        langTitle   = 'Language / Idioma'
        langSelect  = 'Seleccione idioma [1/2]'
        langEnglish = 'English'
        langSpanish = 'Espanol'
        langSet     = 'Idioma cambiado a Espanol.'
    }
}

function T {
    param([string]$Key)
    $lang = if ($Global:Strings.ContainsKey($Global:UiLang)) { $Global:UiLang } else { 'en' }
    $s = $Global:Strings[$lang][$Key]
    if (-not $s) { $s = $Global:Strings['en'][$Key] }
    if (-not $s) { $s = $Key }
    return $s
}

function Load-Settings {
    $Global:UiLang = 'en'
    if (Test-Path -LiteralPath $Global:SettingsFile) {
        try {
            $j = Get-Content -LiteralPath $Global:SettingsFile -Raw | ConvertFrom-Json
            if ($j.lang -in @('en', 'es')) { $Global:UiLang = $j.lang }
        } catch { }
    }
}

function Save-Settings {
    try {
        @{ lang = $Global:UiLang } | ConvertTo-Json | Set-Content -LiteralPath $Global:SettingsFile -Encoding UTF8
    } catch { }
}

# Preferred display columns per log type.
$Global:LogColumns = @{
    traffic       = @('receive_time','src','dst','sport','dport','application','app','action','rule','srcuser','duser','bytes','sessionid')
    threat        = @('receive_time','src','dst','threatid','severity','subtype','action','category','misc','rule','sessionid')
    url           = @('receive_time','src','dst','url','category','action','rule','user','sessionid')
    wildfire      = @('receive_time','src','dst','filetype','file_name','sha256','verdict','action','rule')
    data          = @('receive_time','src','dst','application','app','action','rule','filename','filetype','sessionid')
    decryption    = @('receive_time','src','dst','rule','action','error','proxy','sessionid')
    system        = @('receive_time','severity','subtype','eventid','desc','admin','module')
    auth          = @('receive_time','src','user','action','desc','type')
    userid        = @('receive_time','src','user','action','desc')
    globalprotect = @('receive_time','src','user','event','desc')
    iptag         = @('receive_time','src','tag','event')
    corr          = @('receive_time','src','dst','category','desc')
    gtp           = @('receive_time','src','dst','imsi','imei','desc')
    external      = @('receive_time','src','dst','desc')
    hipmatch      = @('receive_time','src','user','hip','desc')
    config        = @('receive_time','admin','vsys','cmd','path','before-change-detail','after-change-detail','result')
}

# ============================================================
# UI HELPERS
# ============================================================
function Get-ConsoleWidth {
    try { $w = [Console]::WindowWidth } catch { $w = 0 }
    if (-not $w -or $w -lt 40) { $w = 100 }
    return [int]$w
}

function Write-Banner {
    if (-not $Global:Interactive) { return }
    Clear-Host
    $w   = (Get-ConsoleWidth)
    if ($w -lt 40) { $w = 100 }
    $top = [char]0x2554 + ([string][char]0x2550 * ($w - 2)) + [char]0x2557
    $bot = [char]0x255A + ([string][char]0x2550 * ($w - 2)) + [char]0x255D
    $mid = [char]0x2551 + (' ' * ($w - 2)) + [char]0x2551

    function Center-Line { param([string]$Text, [string]$Color)
        $pad  = [math]::Max(0, [math]::Floor(($w - 2 - $Text.Length) / 2))
        $line = [char]0x2551 + (' ' * $pad) + $Text + (' ' * ($w - 2 - $pad - $Text.Length)) + [char]0x2551
        Write-Host $line -ForegroundColor $Color
    }
    Write-Host $top -ForegroundColor $Global:Theme.Border
    Write-Host $mid -ForegroundColor $Global:Theme.Border
    Center-Line (T 'bannerTitle') $Global:Theme.Title
    Center-Line (T 'bannerSubtitle') $Global:Theme.Header
    Center-Line (T 'author') $Global:Theme.Border
    Write-Host $mid -ForegroundColor $Global:Theme.Border
    Write-Host $bot -ForegroundColor $Global:Theme.Border
    Write-Host ''
}

function Write-SectionHeader {
    param([string]$Title)
    if (-not $Global:Interactive) {
        Write-Host ''
        Write-Host "=== $Title ===" -ForegroundColor $Global:Theme.Title
        Write-Host ''
        return
    }
    $w    = (Get-ConsoleWidth)
    if ($w -lt 40) { $w = 100 }
    $line = [string][char]0x2500 * ($w - 4)
    Write-Host ''
    Write-Host ('  ' + [char]0x250C + $line + [char]0x2510) -ForegroundColor $Global:Theme.Border
    $pad  = [math]::Max(0, [math]::Floor(($w - 4 - $Title.Length) / 2))
    $body = (' ' * $pad) + $Title + (' ' * [math]::Max(0, ($w - 4 - $pad - $Title.Length)))
    Write-Host ('  ' + [char]0x2502 + $body + [char]0x2502) -ForegroundColor $Global:Theme.Title
    Write-Host ('  ' + [char]0x2514 + $line + [char]0x2518) -ForegroundColor $Global:Theme.Border
    Write-Host ''
}

function Write-OK   { param([string]$msg) Write-Host "  [OK]  $msg"  -ForegroundColor $Global:Theme.Success }
function Write-ERR  { param([string]$msg) Write-Host "  [ERR] $msg"  -ForegroundColor $Global:Theme.Error }
function Write-WARN { param([string]$msg) Write-Host "  [!]   $msg"  -ForegroundColor $Global:Theme.Warning }
function Write-INFO { param([string]$msg) Write-Host "  [i]   $msg"  -ForegroundColor $Global:Theme.Info }

function Prompt-Input {
    param([string]$Label, [switch]$IsPassword)
    Write-Host "  > $Label`: " -NoNewline -ForegroundColor $Global:Theme.Header
    if ($IsPassword) {
        $sec = Read-Host -AsSecureString
        if (-not $sec) { return '' }
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
        try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
    return Read-Host
}

function Prompt-Confirm {
    param([string]$Question)
    Write-Host "  > $Question [Y/N]: " -NoNewline -ForegroundColor $Global:Theme.Warning
    $r = Read-Host
    return ($r -match '^[yYsS]$')
}

function Pause-Enter {
    if ($Global:Interactive) { Read-Host "`n  $(T 'pressEnter')" | Out-Null }
}

function Write-Menu {
    param(
        [string]$Title,
        [array]$Groups,
        [string]$BackLabel,
        [switch]$NoHeader
    )
    if (-not $NoHeader) { Write-SectionHeader $Title }

    $all = @()
    foreach ($g in $Groups) {
        foreach ($it in @($g.Items)) {
            $all += [PSCustomObject]@{ Key = [string]$it.Key; Label = [string]$it.Label }
        }
    }
    if ($BackLabel) { $all += [PSCustomObject]@{ Key = '0'; Label = $BackLabel } }

    $keyW = 1
    foreach ($it in $all) { if ($it.Key.Length -gt $keyW) { $keyW = $it.Key.Length } }

    $colW = 8
    foreach ($it in $all) {
        $t = ($keyW + 4) + $it.Label.Length
        if ($t -gt $colW) { $colW = $t }
    }
    $colW += 4

    $w = (Get-ConsoleWidth)
    if ($w -lt 60) { $w = 80 }
    $cols = [math]::Max(1, [math]::Floor(($w - 6) / $colW))
    if ($cols -gt 3) { $cols = 3 }

    Write-Host ''
    foreach ($g in $Groups) {
        if ($g.Label) { Write-Host ('  ' + $g.Label) -ForegroundColor $Global:Theme.Highlight }
        $items = @($g.Items)
        for ($i = 0; $i -lt $items.Count; $i++) {
            $it = $items[$i]
            $token = '[' + ([string]$it.Key).PadLeft($keyW) + ']'
            $cell = '    ' + $token + ' ' + [string]$it.Label
            $colIndex = $i % $cols
            $isRowEnd = ($colIndex -eq ($cols - 1)) -or ($i -eq ($items.Count - 1))
            $color = if ($it.Color) { $it.Color } else { $Global:Theme.Menu }
            if ($isRowEnd) { Write-Host $cell -ForegroundColor $color }
            else { Write-Host $cell.PadRight($colW) -NoNewline -ForegroundColor $color }
        }
        Write-Host ''
    }
    if ($BackLabel) {
        $token = '[' + '0'.PadLeft($keyW) + ']'
        Write-Host ('    ' + $token + ' ' + $BackLabel) -ForegroundColor $Global:Theme.Warning
        Write-Host ''
    }
}

# ============================================================
# CONFIGURATION / DEVICE MANAGEMENT
# ============================================================
function Protect-ApiKey {
    param([string]$PlainKey)
    if ([string]::IsNullOrWhiteSpace($PlainKey)) { return '' }
    try { return (ConvertTo-SecureString -String $PlainKey -AsPlainText -Force | ConvertFrom-SecureString) }
    catch { return $PlainKey }
}

function Unprotect-ApiKey {
    param([string]$EncryptedKey)
    if ([string]::IsNullOrWhiteSpace($EncryptedKey)) { return '' }
    try {
        $ss = ConvertTo-SecureString -String $EncryptedKey -ErrorAction Stop
        return (New-Object System.Net.NetworkCredential('', $ss)).Password
    } catch { return $EncryptedKey }
}

function Load-Config {
    $Global:Devices = @()
    if (-not (Test-Path -LiteralPath $Global:ConfigFile)) { return }
    try {
        $raw = Import-Clixml -LiteralPath $Global:ConfigFile -ErrorAction Stop
        $Global:Devices = @($raw | ForEach-Object {
            [PSCustomObject]@{
                Name         = $_.Name
                Host         = $_.Host
                PanOSVersion = if ($_.PanOSVersion) { $_.PanOSVersion } else { $_.Version }
                ApiKey       = Unprotect-ApiKey $_.ApiKey
                AddedDate    = $_.AddedDate
            }
        })
    } catch {
        $Global:Devices = @()
    }
}

function Save-Config {
    if ($Global:Devices.Count -eq 0) {
        if (Test-Path -LiteralPath $Global:ConfigFile) { Remove-Item -LiteralPath $Global:ConfigFile -Force }
        return
    }
    $toSave = $Global:Devices | ForEach-Object {
        [PSCustomObject]@{
            Name         = $_.Name
            Host         = $_.Host
            Version      = $_.PanOSVersion
            PanOSVersion = $_.PanOSVersion
            ApiKey       = (Protect-ApiKey $_.ApiKey)
            AddedDate    = $_.AddedDate
        }
    }
    $toSave | Export-Clixml -LiteralPath $Global:ConfigFile -Force
}

function Get-DeviceIndex {
    if ($Global:Devices.Count -eq 0) {
        Write-WARN (T 'noDevices')
        return -1
    }
    Write-SectionHeader (T 'selectDevice')
    for ($i = 0; $i -lt $Global:Devices.Count; $i++) {
        $d = $Global:Devices[$i]
        Write-Host ('  [{0}]  ' -f ($i + 1)) -NoNewline -ForegroundColor $Global:Theme.Title
        Write-Host $d.Name -NoNewline -ForegroundColor $Global:Theme.Device
        Write-Host ("  ($($d.Host))") -NoNewline -ForegroundColor $Global:Theme.Menu
        Write-Host ("  PAN-OS: $($d.PanOSVersion)") -ForegroundColor $Global:Theme.Info
    }
    Write-Host ''
    $sel = Prompt-Input (T 'deviceNumber')
    $idx = 0
    if (-not [int]::TryParse($sel, [ref]$idx)) { Write-ERR (T 'invalidSelection'); return -1 }
    $idx = $idx - 1
    if ($idx -lt 0 -or $idx -ge $Global:Devices.Count) { Write-ERR (T 'invalidSelection'); return -1 }
    return $idx
}

function Resolve-DeviceObject {
    param([string]$NameOrHost)
    if ([string]::IsNullOrWhiteSpace($NameOrHost)) { return $null }
    return ($Global:Devices | Where-Object { $_.Name -eq $NameOrHost -or $_.Host -eq $NameOrHost } | Select-Object -First 1)
}

function Select-Device {
    if ($Global:Devices.Count -eq 0) { Write-WARN (T 'noDevices'); return $null }
    if ($Global:Devices.Count -eq 1) { return $Global:Devices[0] }
    $idx = Get-DeviceIndex
    if ($idx -lt 0) { return $null }
    return $Global:Devices[$idx]
}

# ============================================================
# PAN-OS API CORE
# ============================================================
function Format-PanError {
    param($Response)
    if (-not $Response) { return (T 'noResponse') }
    $msgs = @()
    try {
        $msgNode = $Response.response.msg
        if ($msgNode) {
            if ($msgNode -is [System.Xml.XmlElement] -and $msgNode.line) {
                foreach ($l in @($msgNode.line)) {
                    if ($l -is [System.Xml.XmlElement]) { $msgs += $l.InnerText } else { $msgs += [string]$l }
                }
            } elseif ($msgNode -is [System.Xml.XmlElement]) {
                $msgs += $msgNode.InnerText
            } else {
                $msgs += [string]$msgNode
            }
        }
        $resNode = $Response.response.result
        if ($resNode -is [System.Xml.XmlElement] -and $resNode.InnerText -and $resNode.InnerText.Trim()) {
            $msgs += $resNode.InnerText.Trim()
        }
    } catch { $msgs += ((T 'couldNotParse') -f $_) }
    if ($msgs.Count -eq 0) {
        $st = $Response.response.status
        if ($st) { return ((T 'unknownApiErrorStatus') -f $st) }
        return (T 'unknownApiError')
    }
    return ($msgs -join ' | ')
}

$Global:FeatureByType = @{
    'log' = 'Log'; 'report' = 'Report'; 'export' = 'Export'; 'import' = 'Import'
    'commit' = 'Commit'; 'config' = 'Configuration'; 'op' = 'Operational Requests'
}

function Get-PanRoleHint {
    param([hashtable]$Params, [string]$ErrorText)
    if ([string]::IsNullOrWhiteSpace($ErrorText)) { return $null }
    if ($ErrorText -notmatch '(?i)(not authorized|insufficient|permission|not permitted|denied|privilege|not allowed|forbidden|unauthoriz|does not have|access denied)') { return $null }
    $t = if ($Params) { [string]$Params.type } else { '' }
    if ($t -eq 'op' -and $Params.cmd -match '<debug>') { return (T 'hintPermDebug') }
    $feat = $Global:FeatureByType[$t]
    if ($feat) { return ((T 'hintPermFeature') -f $feat) }
    return (T 'hintPermGeneric')
}

function Get-ApiKey {
    param([string]$FWHost, [string]$User, [string]$Password)
    $uri = "https://$FWHost/api/"
    try {
        $resp = Invoke-RestMethod -Uri $uri -Method Post -Body @{ type = 'keygen'; user = $User; password = $Password } `
            -SkipCertificateCheck -TimeoutSec 30 -ErrorAction Stop
        if ($resp.response.status -eq 'success') { return $resp.response.result.key }
        Write-ERR ((T 'couldNotGetKey') -f (Format-PanError $resp))
        return $null
    } catch {
        Write-ERR ((T 'connectionError') -f $_.Exception.Message)
        return $null
    }
}

function Invoke-PanApi {
    param(
        [string]$FWHost,
        [string]$ApiKey,
        [hashtable]$Params,
        [int]$TimeoutSec = 30,
        [switch]$Silent
    )
    if (-not $ApiKey) { if (-not $Silent) { Write-ERR (T 'missingApiKey') }; return $null }
    $headers = @{ 'X-PAN-KEY' = $ApiKey }
    $uri = "https://$FWHost/api/"
    try {
        $resp = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $Params `
            -SkipCertificateCheck -TimeoutSec $TimeoutSec -ErrorAction Stop
        if (-not $Silent -and $resp -and $resp.response.status -eq 'error') {
            $hint = Get-PanRoleHint -Params $Params -ErrorText (Format-PanError $resp)
            if ($hint) { Write-WARN $hint }
        }
        return $resp
    } catch {
        if (-not $Silent) { Write-ERR ((T 'apiError') -f $FWHost, $_.Exception.Message) }
        return $null
    }
}

function Invoke-PanOp {
    param($Device, [string]$Cmd, [int]$TimeoutSec = 60, [switch]$Silent)
    return (Invoke-PanApi -FWHost $Device.Host -ApiKey $Device.ApiKey -Params @{ type = 'op'; cmd = $Cmd } -TimeoutSec $TimeoutSec -Silent:$Silent)
}

function Test-DeviceConnection {
    param($Device)
    $resp = Invoke-PanOp -Device $Device -Cmd '<show><system><info></info></system></show>' -TimeoutSec 20 -Silent
    if ($resp -and $resp.response.status -eq 'success') { return $resp.response.result.system }
    return $null
}

function Test-ApiPermissions {
    param($Device)
    Write-SectionHeader (T 'permTitle')
    $probes = [ordered]@{
        (T 'permOp')     = @{ type = 'op'; cmd = '<show><system><info></info></system></show>' }
        (T 'permConfig') = @{ type = 'config'; action = 'get'; xpath = '/config/devices/entry/vsys' }
        (T 'permLog')    = @{ type = 'log'; 'log-type' = 'config'; nlogs = 1 }
        (T 'permReport') = @{ type = 'report'; reporttype = 'dynamic' }
    }
    foreach ($name in $probes.Keys) {
        $resp = Invoke-PanApi -FWHost $Device.Host -ApiKey $Device.ApiKey -Params $probes[$name] -TimeoutSec 30 -Silent
        if ($resp -and $resp.response.status -eq 'success') {
            Write-Host ('  [OK]    ' + $name) -ForegroundColor $Global:Theme.Good
        } else {
            Write-Host ('  [DENY]  ' + $name + ' -> ' + (Format-PanError $resp)) -ForegroundColor $Global:Theme.Bad
        }
    }
    Write-Host ''
    Write-INFO (T 'permHint')
}

function Wait-PanJob {
    param($Device, [string]$JobId, [string]$Type, [int]$MaxWaitSec = 180, [int]$PollSec = 2)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $MaxWaitSec) {
        Start-Sleep -Seconds $PollSec
        $poll = Invoke-PanApi -FWHost $Device.Host -ApiKey $Device.ApiKey `
            -Params @{ type = $Type; action = 'get'; 'job-id' = $JobId } -TimeoutSec 60 -Silent
        if (-not $poll) { continue }
        $r = $poll.response.result
        if ($r.log -or $r.report -or $r.'report-data') { return $poll }
        if ($r.job) {
            $st = if ($r.job -is [string]) { $r.job } else { [string]$r.job.status }
            if ($st -eq 'FIN') { return $poll }
        }
    }
    Write-WARN ((T 'jobTimeout') -f $JobId)
    return $null
}

# ============================================================
# XML / OBJECT HELPERS
# ============================================================
function Get-XmlText {
    param($Node)
    if ($null -eq $Node) { return '' }
    if ($Node -is [System.Xml.XmlElement]) { return $Node.InnerText }
    return [string]$Node
}

function ConvertFrom-PanLogEntry {
    param($Entry)
    $h = [ordered]@{}
    if ($Entry -is [System.Xml.XmlElement] -and $Entry.HasAttributes) {
        foreach ($a in $Entry.Attributes) { $h[$a.Name] = $a.Value }
    }
    foreach ($c in $Entry.ChildNodes) {
        if ($c.NodeType -eq [System.Xml.XmlNodeType]::Element) {
            if (-not $h.Contains($c.Name)) { $h[$c.Name] = $c.InnerText }
        }
    }
    return [PSCustomObject]$h
}

function Out-Table {
    param($Objects, [string[]]$Preferred)
    $arr = @($Objects)
    if ($arr.Count -eq 0) { Write-WARN (T 'noResults'); return }
    $props = $arr[0].PSObject.Properties.Name
    $cols = @()
    if ($Preferred) { $cols = @($Preferred | Where-Object { $props -contains $_ }) }
    if ($cols.Count -eq 0) { $cols = $props }
    $text = ($arr | Select-Object $cols | Format-Table -AutoSize | Out-String -Width 8192)
    Write-Host $text
}

function Get-StatusColor {
    param([string]$Text)
    $t = [string]$Text
    if ($t -match '(?i)^\s*(ok|allow|allowed|accept|success|succeeded|valid|up|active|enabled|installed|complete|fin|yes|permit|permitted|green)') { return $Global:Theme.Good }
    if ($t -match '(?i)(fail|failed|error|deny|denied|drop|dropped|block|blocked|reset|sinkhole|reject|expired|down|inactive|invalid|disabled|revoked|timeout|unreachable|no\b)') { return $Global:Theme.Bad }
    if ($t -match '(?i)(pend|queued|act\b|soon|warning|partial|unknown|standby|passive|expiring)') { return $Global:Theme.Caution }
    return $Global:Theme.Neutral
}

function Get-SeverityColor {
    param([string]$Text)
    switch -regex ([string]$Text) {
        '(?i)critical' { return $Global:Theme.Bad }
        '(?i)high'     { return $Global:Theme.Bad }
        '(?i)medium'   { return $Global:Theme.Caution }
        '(?i)low'      { return $Global:Theme.Neutral }
        default        { return $Global:Theme.Neutral }
    }
}

function Out-ColorTable {
    param(
        $Objects,
        [string[]]$Columns,
        [hashtable]$ColorMap,
        [string]$DefaultColor = 'Gray'
    )
    $arr = @($Objects)
    if ($arr.Count -eq 0) { Write-WARN (T 'noResults'); return }
    $props = $arr[0].PSObject.Properties.Name
    $cols = @()
    if ($Columns) { $cols = @($Columns | Where-Object { $props -contains $_ }) }
    if ($cols.Count -eq 0) { $cols = $props }

    $matrix = @()
    foreach ($row in $arr) {
        $cells = @()
        foreach ($c in $cols) {
            $v = $row.$c
            if ($null -eq $v) { $cells += '' } else { $cells += ((([string]$v) -replace '\s+', ' ').Trim()) }
        }
        $matrix += , $cells
    }

    $widths = @{}
    for ($i = 0; $i -lt $cols.Count; $i++) {
        $w = ([string]$cols[$i]).Length
        foreach ($r in $matrix) {
            $len = ([string]$r[$i]).Length
            if ($len -gt $w) { $w = $len }
        }
        if ($w -gt 60) { $w = 60 }
        $widths[$i] = $w
    }

    $header = ''
    for ($i = 0; $i -lt $cols.Count; $i++) {
        $header += ([string]$cols[$i]).PadRight($widths[$i]) + ' '
    }
    Write-Host ('  ' + $header.TrimEnd()) -ForegroundColor $Global:Theme.Header
    Write-Host ('  ' + ('-' * ([math]::Min(240, $header.Length)))) -ForegroundColor $Global:Theme.Border

    foreach ($r in $matrix) {
        Write-Host '  ' -NoNewline
        for ($i = 0; $i -lt $cols.Count; $i++) {
            $text = [string]$r[$i]
            if ($text.Length -gt $widths[$i]) { $text = $text.Substring(0, $widths[$i]) }
            $color = $DefaultColor
            if ($ColorMap -and $ColorMap.ContainsKey($cols[$i])) {
                try { $color = & $ColorMap[$cols[$i]] $text } catch { $color = $DefaultColor }
            }
            Write-Host ($text.PadRight($widths[$i]) + ' ') -NoNewline -ForegroundColor $color
        }
        Write-Host ''
    }
}

function ConvertFrom-PanXmlList {
    param($Nodes, [hashtable]$Map)
    $arr = @($Nodes)
    $out = foreach ($n in $arr) {
        $h = [ordered]@{}
        foreach ($k in $Map.Keys) {
            $h[$k] = Get-XmlText $n.($Map[$k])
        }
        [PSCustomObject]$h
    }
    return @($out)
}

$script:VsysCache = @{}
function Get-VsysName {
    param($Device)
    if ($script:VsysCache.ContainsKey($Device.Host)) { return $script:VsysCache[$Device.Host] }
    $name = 'vsys1'
    $resp = Invoke-PanApi -FWHost $Device.Host -ApiKey $Device.ApiKey -Params @{ type = 'config'; action = 'get'; xpath = '/config/devices/entry/vsys' } -Silent
    if ($resp -and $resp.response.status -eq 'success') {
        $entry = $resp.response.result.vsys.entry
        if ($entry) {
            $first = @($entry)[0]
            if ($first.name) { $name = [string]$first.name }
        }
    }
    $script:VsysCache[$Device.Host] = $name
    return $name
}

function Export-Results {
    param($Objects, [string]$BaseName, [string]$Format, [string]$OutDir)
    $arr = @($Objects)
    if ($arr.Count -eq 0) { Write-WARN (T 'nothingToExport'); return }
    if (-not $OutDir) { $OutDir = '.' }
    if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
    $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
    try {
        if ($Format -eq 'json') {
            $path = Join-Path $OutDir "$BaseName-$ts.json"
            $arr | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8
        } else {
            $path = Join-Path $OutDir "$BaseName-$ts.csv"
            $arr | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
        }
        Write-OK ((T 'exported') -f $path)
    } catch {
        Write-ERR ((T 'exportFailed') -f $_.Exception.Message)
    }
}

function Invoke-ExportPrompt {
    param($Objects, [string]$BaseName)
    if (-not $Global:Interactive) { return }
    if (@($Objects).Count -eq 0) { return }
    if (-not (Prompt-Confirm (T 'askExport'))) { return }
    $fmt = Prompt-Input (T 'exportFormatPrompt')
    if ($fmt -notin @('csv', 'json')) { $fmt = 'csv' }
    Export-Results -Objects $Objects -BaseName $BaseName -Format $fmt -OutDir $Global:OutputDir
}

function Export-XmlContent {
    param([string]$Content, [string]$BaseName)
    if ([string]::IsNullOrWhiteSpace($Content)) { Write-WARN (T 'nothingToExport'); return }
    $OutDir = $Global:OutputDir
    if (-not $OutDir) { $OutDir = '.' }
    if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
    $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
    try {
        $path = Join-Path $OutDir "$BaseName-$ts.xml"
        $Content | Set-Content -LiteralPath $path -Encoding UTF8
        Write-OK ((T 'exported') -f $path)
    } catch {
        Write-ERR ((T 'exportFailed') -f $_.Exception.Message)
    }
}

function Get-LogsFromResponse {
    param($Resp)
    try {
        $log = $Resp.response.result.log
        if (-not $log) { return @() }
        $e = $log.logs.entry
        if (-not $e) { return @() }
        return @($e)
    } catch { return @() }
}

# ============================================================
# LOG QUERY / TIME HELPERS
# ============================================================
function Resolve-Since {
    param([string]$Last)
    if ([string]::IsNullOrWhiteSpace($Last)) { $Last = '24h' }
    if ($Last -match '^\d{4}/\d{2}/\d{2}') { return $Last }
    if ($Last -match '^(\d+)\s*([smhd])$') {
        $n = [int]$matches[1]
        $span = switch ($matches[2]) {
            's' { [timespan]::FromSeconds($n) }
            'm' { [timespan]::FromMinutes($n) }
            'h' { [timespan]::FromHours($n) }
            'd' { [timespan]::FromDays($n) }
        }
        return (Get-Date).Add(-$span).ToString('yyyy/MM/dd HH:mm:ss')
    }
    return (Get-Date).AddDays(-1).ToString('yyyy/MM/dd HH:mm:ss')
}

function New-PanLogQuery {
    param(
        [string]$Since, [string]$Until, [string]$Src, [string]$Dst,
        [string]$Dport, [string]$Sport, [string]$App, [string]$Domain,
        [string]$Url, [string]$Severity, [string]$Rule, [string]$User, [string]$Extra
    )
    $c = @()
    if ($Since)    { $c += "(receive_time geq '$Since')" }
    if ($Until)    { $c += "(receive_time leq '$Until')" }
    if ($Src)      { $c += "(addr.src in $Src)" }
    if ($Dst)      { $c += "(addr.dst in $Dst)" }
    if ($Dport)    { $c += "(port.dst eq $Dport)" }
    if ($Sport)    { $c += "(port.src eq $Sport)" }
    if ($App)      { $c += "(app eq $App)" }
    if ($Domain)   { $c += "(misc contains $Domain)" }
    if ($Url)      { $c += "(url contains $Url)" }
    if ($Severity) { $c += "(severity eq $Severity)" }
    if ($Rule)     { $c += "(rule eq '$Rule')" }
    if ($User)     { $c += "(srcuser eq '$User')" }
    if ($Extra)    { $c += "($Extra)" }
    return ($c -join ' and ')
}

function Get-PanLog {
    param(
        $Device, [string]$LogType, [string]$Query,
        [int]$Limit = 100, [int]$Skip = 0, [string]$Dir = 'backward', [int]$MaxWaitSec = 180
    )
    $params = @{ type = 'log'; 'log-type' = $LogType; nlogs = $Limit; skip = $Skip; dir = $Dir }
    if ($Query) { $params.query = $Query }
    $resp = Invoke-PanApi -FWHost $Device.Host -ApiKey $Device.ApiKey -Params $params -TimeoutSec 60
    if (-not $resp) { return @() }
    if ($resp.response.status -ne 'success') {
        Write-ERR ((T 'logQueryFailed') -f (Format-PanError $resp))
        return @()
    }
    $entries = Get-LogsFromResponse $resp
    if ($entries.Count -gt 0) { return $entries }
    $job = $resp.response.result.job
    if ($job) {
        $final = Wait-PanJob -Device $Device -JobId $job -Type 'log' -MaxWaitSec $MaxWaitSec
        if ($final) { return (Get-LogsFromResponse $final) }
    }
    return @()
}

function Show-LogAggregate {
    param($Objects)
    $arr = @($Objects)
    if ($arr.Count -eq 0) { return }
    $props = $arr[0].PSObject.Properties.Name
    $appCol = if ($props -contains 'app') { 'app' } elseif ($props -contains 'application') { 'application' } else { $null }
    Write-Host ''
    Write-SectionHeader (T 'logAggregate')
    foreach ($col in @($appCol, 'src', 'dst', 'action', 'severity')) {
        if (-not $col) { continue }
        if ($props -notcontains $col) { continue }
        $top = @($arr | Where-Object { $_.$col } | Group-Object { $_.$col } | Sort-Object Count -Descending | Select-Object -First 10)
        if ($top.Count -eq 0) { continue }
        $rows = @($top | ForEach-Object { [PSCustomObject]@{ Value = $_.Name; Count = $_.Count } })
        Write-Host ''
        Write-Host ('  ' + $col) -ForegroundColor $Global:Theme.Header
        Out-ColorTable -Objects $rows -Columns @('Value', 'Count')
    }
}

function Invoke-LogSearch {
    param($Device, [string]$LogType, [string]$Query, [int]$Limit, [string]$Dir = 'backward', [switch]$Aggregate, [switch]$DoExport)
    if (-not $Query) {
        Write-WARN (T 'emptyQuery')
        return @()
    }
    Write-INFO ((T 'query') -f $Query)
    Write-INFO ((T 'retrievingLogs') -f $LogType, $Limit)
    $entries = Get-PanLog -Device $Device -LogType $LogType -Query $Query -Limit $Limit -Skip $Skip -Dir $Dir
    $objs = @($entries | ForEach-Object { ConvertFrom-PanLogEntry $_ })
    Write-Host ''
    Write-INFO ((T 'entriesReturned') -f $objs.Count)
    $pref = $Global:LogColumns[$LogType]
    Out-ColorTable -Objects $objs -Columns $pref -ColorMap @{
        'action'   = { param($v) Get-StatusColor $v }
        'action2'  = { param($v) Get-StatusColor $v }
        'severity' = { param($v) Get-SeverityColor $v }
        'result'   = { param($v) Get-StatusColor $v }
        'cmd'      = { param($v) if ($v -match '(?i)delete') { $Global:Theme.Bad } elseif ($v -match '(?i)commit') { $Global:Theme.Good } else { $Global:Theme.Caution } }
    }
    if ($Aggregate) { Show-LogAggregate -Objects $objs }
    if ($DoExport -or $Export) {
        Export-Results -Objects $objs -BaseName "pan-$LogType" -Format $Format -OutDir $Global:OutputDir
    }
    return $objs
}

# ============================================================
# ROBUST QUERY HELPERS
# ============================================================
function Test-PanQuery {
    param($Device, [string]$LogType, [string]$Query, [int]$Limit = 200, [int]$Skip = 0, [string]$Dir = 'backward')
    $params = @{ type = 'log'; 'log-type' = $LogType; nlogs = $Limit; skip = $Skip; dir = $Dir }
    if ($Query) { $params.query = $Query }
    $resp = Invoke-PanApi -FWHost $Device.Host -ApiKey $Device.ApiKey -Params $params -TimeoutSec 60 -Silent
    if (-not $resp) { return [PSCustomObject]@{ Ok = $false; Entries = @(); Error = (T 'noResponse') } }
    if ($resp.response.status -ne 'success') {
        return [PSCustomObject]@{ Ok = $false; Entries = @(); Error = (Format-PanError $resp) }
    }
    $entries = Get-LogsFromResponse $resp
    if ($entries.Count -eq 0) {
        $job = $resp.response.result.job
        if ($job) {
            $final = Wait-PanJob -Device $Device -JobId $job -Type 'log' -MaxWaitSec 120
            if ($final) { $entries = Get-LogsFromResponse $final }
        }
    }
    return [PSCustomObject]@{ Ok = $true; Entries = $entries; Error = '' }
}

$script:DnsSubtype = $null
function Get-DnsSubtype {
    param($Device, [string]$Since)
    if ($script:DnsSubtype) { return $script:DnsSubtype }
    foreach ($c in @('dns', 'dns-security', 'dnsproxy', 'dns-proxy', 'dns_security')) {
        $r = Test-PanQuery -Device $Device -LogType 'threat' -Query "(subtype eq $c) and (receive_time geq '$Since')" -Limit 1
        if ($r.Ok) { $script:DnsSubtype = $c; return $c }
    }
    return $null
}

function Get-DnsSubtypeList {
    param($Device, [string]$Since)
    $r = Test-PanQuery -Device $Device -LogType 'threat' -Query "(receive_time geq '$Since')" -Limit 1000
    if (-not $r.Ok) { return @() }
    $objs = @($r.Entries | ForEach-Object { ConvertFrom-PanLogEntry $_ })
    return @($objs | Where-Object { $_.subtype } | Group-Object subtype |
        Sort-Object Count -Descending | ForEach-Object {
            [PSCustomObject]@{ Subtype = $_.Name; Count = $_.Count }
        })
}

# ============================================================
# DNS SECURITY CHECK
# ============================================================
function Test-UrlFiltering {
    param($Device, [string]$DomainOrUrl)
    if ([string]::IsNullOrWhiteSpace($DomainOrUrl)) { return $null }
    $target = if ($DomainOrUrl -match '^https?://') { $DomainOrUrl } else { "http://$DomainOrUrl" }
    $cmd = "<test><url>$target</url></test>"
    return (Invoke-PanOp -Device $Device -Cmd $cmd -TimeoutSec 30 -Silent)
}

function Test-DnsSecurity {
    param($Device, [string]$Domain, [string]$Last = '7d', [switch]$DoExport)
    $since = Resolve-Since $Last
    Write-INFO (T 'dnsCheck')
    Write-INFO ((T 'dnsWindow') -f $since)
    if ($Domain) { Write-INFO ((T 'dnsDomain') -f $Domain) }
    Write-Host ''

    Write-INFO (T 'dnsSearchThreat')
    $subtype = Get-DnsSubtype -Device $Device -Since $since
    $threatObjs = @()
    if ($subtype) {
        Write-INFO ((T 'dnsUsingSubtype') -f $subtype)
        $q = "(subtype eq $subtype) and (receive_time geq '$since')"
        if ($Domain) { $q = "(subtype eq $subtype) and (misc contains $Domain) and (receive_time geq '$since')" }
        $r = Test-PanQuery -Device $Device -LogType 'threat' -Query $q -Limit 2000
        if ($r.Ok) { $threatObjs = @($r.Entries | ForEach-Object { ConvertFrom-PanLogEntry $_ }) }
    }
    if ($threatObjs.Count -eq 0 -and $Domain) {
        Write-INFO (T 'dnsFallback')
        $rf = Test-PanQuery -Device $Device -LogType 'threat' -Query "(misc contains $Domain) and (receive_time geq '$since')" -Limit 2000
        if ($rf.Ok) { $threatObjs = @($rf.Entries | ForEach-Object { ConvertFrom-PanLogEntry $_ }) }
    }

    Write-INFO (T 'dnsSearchUrl')
    $urlObjs = @()
    $urlQuery = "(receive_time geq '$since')"
    if ($Domain) { $urlQuery = "(misc contains $Domain) and $urlQuery" }
    $ru = Test-PanQuery -Device $Device -LogType 'url' -Query $urlQuery -Limit 1000
    if ($ru.Ok) { $urlObjs = @($ru.Entries | ForEach-Object { ConvertFrom-PanLogEntry $_ }) }

    $all = @($threatObjs + $urlObjs)
    if ($Domain) {
        $esc = [regex]::Escape($Domain)
        $all = @($all | Where-Object {
                $hit = $false
                foreach ($v in $_.PSObject.Properties.Value) {
                    if ($v -is [string] -and $v -match $esc) { $hit = $true; break }
                }
                $hit
            })
    }
    $all = @($all | ForEach-Object {
            $act = [string]$_.action
            $status = if ($act -match '(?i)block|drop|deny|reset|sinkhole|reject') { 'BLOCKED' } else { 'ALLOWED' }
            $_ | Add-Member -NotePropertyName Status -NotePropertyValue $status -Force -PassThru
        })
    $blocked = @($all | Where-Object { $_.Status -eq 'BLOCKED' })

    Write-Host ''
    Write-SectionHeader (T 'dnsResultHeader')
    if ($Domain) {
        if ($blocked.Count -gt 0) {
            Write-Host ('  ' + ((T 'dnsBlocked') -f $blocked.Count, $Domain)) -ForegroundColor $Global:Theme.Bad
        } elseif ($all.Count -gt 0) {
            Write-Host ('  ' + ((T 'dnsAllowed') -f $Domain)) -ForegroundColor $Global:Theme.Good
        } else {
            Write-Host ('  ' + ((T 'dnsNoData') -f $Domain)) -ForegroundColor $Global:Theme.Caution
        }
    } else {
        Write-INFO ((T 'dnsEventsCount') -f $threatObjs.Count)
        Write-INFO ((T 'dnsUrlCount') -f $urlObjs.Count)
    }

    if ($all.Count -gt 0) {
        Write-Host ''
        Out-ColorTable -Objects $all `
            -Columns @('receive_time', 'src', 'dst', 'subtype', 'severity', 'category', 'misc', 'action', 'Status') `
            -ColorMap @{
                'action'   = { param($v) Get-StatusColor $v }
                'Status'   = { param($v) Get-StatusColor $v }
                'severity' = { param($v) Get-SeverityColor $v }
            }
    } else {
        Write-INFO (T 'dnsNoEvents')
    }

    Write-Host ''
    Write-INFO (T 'dnsUrlTest')
    if ($Domain) {
        $ur = Test-UrlFiltering -Device $Device -DomainOrUrl $Domain
        if ($ur -and $ur.response.status -eq 'success') {
            $line = if ($ur.response.result -is [System.Xml.XmlElement]) { $ur.response.result.InnerText } else { [string]$ur.response.result }
            Write-Host ('  ' + ((T 'dnsUrlTestResult') -f $line)) -ForegroundColor $Global:Theme.Info
        } else {
            Write-WARN ((T 'dnsUrlTestUnavail') -f (Format-PanError $ur))
        }
    }

    if ($DoExport -or $Export) {
        Export-Results -Objects $all -BaseName 'pan-dns-security' -Format $Format -OutDir $Global:OutputDir
    }
    return $all
}

function Test-FlowSecurity {
    param($Device, [string]$Src, [string]$Dst, [string]$Port, [string]$App, [string]$Protocol = '6', [string]$Last = '24h', [switch]$DoExport)
    if (-not $Dst) { Write-WARN (T 'o2dDstReq'); return @() }
    $since = Resolve-Since $Last
    $isIp = $Dst -match '^\d{1,3}(\.\d{1,3}){3}$'
    $isDomain = (-not $isIp) -and ($Dst -match '[A-Za-z]')
    $dstIp = if ($isIp) { $Dst } else { '' }

    Write-SectionHeader (T 'o2dResultHeader')
    Write-INFO ((T 'o2dLine') -f $(if ($Src) { $Src } else { '*' }), $Dst, $(if ($Port) { $Port } else { '*' }), $(if ($App) { $App } else { '*' }))

    $trafficObjs = @()
    $tq = "(receive_time geq '$since')"
    if ($Src) { $tq += " and (addr.src in $Src)" }
    if ($dstIp) { $tq += " and (addr.dst in $dstIp)" }
    if ($Port) { $tq += " and (port.dst eq $Port)" }
    if ($App) { $tq += " and (app eq $App)" }
    $tr = Test-PanQuery -Device $Device -LogType 'traffic' -Query $tq -Limit 500
    if ($tr.Ok) { $trafficObjs = @($tr.Entries | ForEach-Object { ConvertFrom-PanLogEntry $_ }) }

    $threatObjs = @()
    $hq = "(receive_time geq '$since')"
    if ($Src) { $hq += " and (addr.src in $Src)" }
    if ($dstIp) { $hq += " and (addr.dst in $dstIp)" }
    if ($isDomain) { $hq += " and (misc contains $Dst)" }
    $th = Test-PanQuery -Device $Device -LogType 'threat' -Query $hq -Limit 500
    if ($th.Ok) { $threatObjs = @($th.Entries | ForEach-Object { ConvertFrom-PanLogEntry $_ }) }

    $urlObjs = @()
    $testUrlLine = ''
    if ($isDomain) {
        $uq = "(receive_time geq '$since') and (misc contains $Dst)"
        if ($Src) { $uq += " and (addr.src in $Src)" }
        $ur = Test-PanQuery -Device $Device -LogType 'url' -Query $uq -Limit 500
        if ($ur.Ok) { $urlObjs = @($ur.Entries | ForEach-Object { ConvertFrom-PanLogEntry $_ }) }
        $tu = Test-UrlFiltering -Device $Device -DomainOrUrl $Dst
        if ($tu -and $tu.response.status -eq 'success') {
            $testUrlLine = if ($tu.response.result -is [System.Xml.XmlElement]) { $tu.response.result.InnerText } else { [string]$tu.response.result }
        }
    }

    # Policy match (needs src + dst IP; infer dst IP from logs if domain)
    $policyText = ''
    if (-not $dstIp) {
        $cand = @(@($trafficObjs + $threatObjs + $urlObjs) | Where-Object { $_.dst -match '^\d{1,3}(\.\d{1,3}){3}$' } | Group-Object dst | Sort-Object Count -Descending | Select-Object -First 1)
        if ($cand.Count -gt 0) { $dstIp = $cand[0].Name }
    }
    if ($Src -and $dstIp) {
        $resp = Test-PolicyMatch -Device $Device -Src $Src -Dst $dstIp -Port $Port -App $App -Protocol $Protocol
        if ($resp) { $policyText = Get-OpText $resp }
    }

    $trafficDeny = @($trafficObjs | Where-Object { [string]$_.action -match '(?i)deny|drop|reset|block' })
    $threatBlock = @($threatObjs | Where-Object { [string]$_.action -match '(?i)block|drop|deny|reset|sinkhole|reject' })
    $urlBlock = @($urlObjs | Where-Object { [string]$_.action -match '(?i)block|drop|deny|reset' })
    $policyDeny = ($policyText -match '(?i)(^|\s)(deny|drop|reset)(\s|$)')

    $level = 'UNKNOWN'
    if ($trafficDeny.Count -gt 0 -or $threatBlock.Count -gt 0 -or $urlBlock.Count -gt 0 -or $policyDeny) { $level = 'BLOCKED' }
    elseif ($trafficObjs.Count -gt 0 -or $threatObjs.Count -gt 0 -or $urlObjs.Count -gt 0 -or ($policyText -ne '')) { $level = 'ALLOWED' }

    $rows = @()
    $polRes = if ($Src -and $dstIp) { if ($policyText) { ($policyText -split "`r?`n" | Where-Object { $_.Trim() -ne '' -and $_ -notmatch '^(?i)\s*rule\s+action' -and $_ -notmatch '^-+\s' } | Select-Object -First 1) } else { '?' } } elseif ($dstIp) { (T 'o2dNeedSrc') } else { (T 'o2dNoDstIp') }
    $rows += [PSCustomObject]@{ Layer = (T 'o2dPolicy'); Result = $polRes }
    $tactions = (@($trafficObjs | Group-Object action | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', ')
    $rows += [PSCustomObject]@{ Layer = (T 'o2dTraffic'); Result = ((T 'o2dEvents') -f $trafficObjs.Count) + $(if ($tactions) { "  [$tactions]" } else { '' }) }
    $rows += [PSCustomObject]@{ Layer = (T 'o2dDns'); Result = ((T 'o2dBlocks') -f $threatBlock.Count) + " / " + ((T 'o2dEvents') -f $threatObjs.Count) }
    if ($isDomain) {
        $rows += [PSCustomObject]@{ Layer = (T 'o2dUrl'); Result = ((T 'o2dBlocks') -f $urlBlock.Count) + " / " + ((T 'o2dEvents') -f $urlObjs.Count) }
    }

    Write-Host ''
    $color = switch ($level) { 'BLOCKED' { $Global:Theme.Bad } 'ALLOWED' { $Global:Theme.Good } default { $Global:Theme.Caution } }
    Write-Host ('  ' + ((T "o2dVerdict$level") -f $Dst)) -ForegroundColor $color
    Write-Host ''
    Out-ColorTable -Objects $rows -Columns @('Layer', 'Result') -ColorMap @{
        'Result' = { param($v) Get-StatusColor $v }
    }
    if ($testUrlLine) {
        Write-Host ('    ' + ((T 'dnsUrlTestResult') -f $testUrlLine)) -ForegroundColor $Global:Theme.Info
    }

    if ($policyText) {
        Write-Host ''
        Write-Host ('  ' + (T 'o2dPolicy') + ':') -ForegroundColor $Global:Theme.Header
        foreach ($l in ($policyText -split "`r?`n")) { if ($l.Trim()) { Write-Host ('    ' + $l.Trim()) -ForegroundColor $Global:Theme.Info } }
    }

    $ev = @($trafficObjs + $threatObjs + $urlObjs)
    if ($ev.Count -gt 0) {
        Write-Host ''
        Out-ColorTable -Objects $ev -Columns @('receive_time', 'src', 'dst', 'application', 'dport', 'action', 'rule', 'misc') -ColorMap @{
            'action' = { param($v) Get-StatusColor $v }
        }
    } else {
        Write-INFO (T 'dnsNoEvents')
    }

    if ($DoExport -or $Export) { Export-Results -Objects $ev -BaseName 'pan-flow-test' -Format $Format -OutDir $Global:OutputDir }
    return $ev
}

$script:VrCache = @{}
function Get-VirtualRouterName {
    param($Device)
    if ($script:VrCache.ContainsKey($Device.Host)) { return $script:VrCache[$Device.Host] }
    $vr = 'default'
    $vsys = Get-VsysName -Device $Device
    $resp = Invoke-PanApi -FWHost $Device.Host -ApiKey $Device.ApiKey -Params @{ type = 'config'; action = 'get'; xpath = "/config/devices/entry/vsys/entry[@name='$vsys']/network/virtual-router" } -Silent
    if ($resp -and $resp.response.status -eq 'success') {
        $e = $resp.response.result.'virtual-router'.entry
        if ($e) { $first = @($e)[0]; if ($first.name) { $vr = [string]$first.name } }
    }
    $script:VrCache[$Device.Host] = $vr
    return $vr
}

function Test-FibLookup {
    param($Device, [string]$Ip)
    if (-not $Ip) { return '' }
    $vr = Get-VirtualRouterName -Device $Device
    $candidates = @(
        "<test><routing><fib-lookup><virtual-router>$vr</virtual-router><ip>$Ip</ip></fib-lookup></routing></test>",
        "<test><routing><fib-lookup><virtual-router>$vr</virtual-router><destination>$Ip</destination></fib-lookup></routing></test>"
    )
    foreach ($cmd in $candidates) {
        $resp = Invoke-PanOp -Device $Device -Cmd $cmd -TimeoutSec 20 -Silent
        if ($resp -and $resp.response.status -eq 'success') {
            $txt = Get-OpText $resp
            if ($txt -and $txt -notmatch '(?i)unexpected|invalid|not found') { return $txt }
        }
    }
    return ''
}

function Get-DnsProxyResolutions {
    param($Device, [string]$Domain)
    if (-not $Domain) { return @() }
    $out = @()
    foreach ($cmd in @('<show><dns-proxy><cache>all</cache></dns-proxy></show>', '<show><dns-proxy><fqdn>all</fqdn></dns-proxy></show>')) {
        $resp = Invoke-PanOp -Device $Device -Cmd $cmd -TimeoutSec 20 -Silent
        if ($resp -and $resp.response.status -eq 'success') {
            foreach ($ln in ((Get-OpText $resp) -split "`r?`n")) {
                if ($ln -match [regex]::Escape($Domain)) {
                    foreach ($m in [regex]::Matches($ln, '\b\d{1,3}(\.\d{1,3}){3}\b')) { $out += $m.Value }
                }
            }
        }
        if ($out.Count -gt 0) { break }
    }
    return @($out | Select-Object -Unique)
}

function Resolve-TargetIps {
    param($Device, [string]$Domain, [string]$Last = '24h')
    $ips = @(); $source = ''; $pingText = ''
    if (-not $Domain) { return [PSCustomObject]@{ Ips = @(); Source = ''; Ping = '' } }
    # 1) ping host via firewall management DNS
    $resp = Invoke-PanOp -Device $Device -Cmd "<ping><host>$Domain</host><count>1</count></ping>" -TimeoutSec 20 -Silent
    if ($resp -and $resp.response.status -eq 'success') {
        $pingText = Get-OpText $resp
        foreach ($m in [regex]::Matches($pingText, '\((\d{1,3}(?:\.\d{1,3}){3})\)')) { $ips += $m.Groups[1].Value }
        if ($ips.Count -gt 0) { $source = 'ping' }
    }
    # 2) dns-proxy cache / fqdn
    if ($ips.Count -eq 0) {
        $ips = @(Get-DnsProxyResolutions -Device $Device -Domain $Domain)
        if ($ips.Count -gt 0) { $source = 'cache' }
    }
    # 3) IPs observed in url/threat logs for the domain
    if ($ips.Count -eq 0) {
        $since = Resolve-Since $Last
        foreach ($lt in @('url', 'threat')) {
            $r = Test-PanQuery -Device $Device -LogType $lt -Query "(misc contains $Domain) and (receive_time geq '$since')" -Limit 200
            if ($r.Ok) {
                foreach ($e in @($r.Entries | ForEach-Object { ConvertFrom-PanLogEntry $_ })) {
                    if ([string]$e.dst -match '^\d{1,3}(\.\d{1,3}){3}$') { $ips += [string]$e.dst }
                }
            }
        }
        if ($ips.Count -gt 0) { $source = 'logs' }
    }
    return [PSCustomObject]@{ Ips = @($ips | Select-Object -Unique); Source = $source; Ping = $pingText }
}

function Show-DnsDiagnosis {
    param($Device, [string]$Domain, [string]$PingText, [string]$Since)
    Write-Host ''
    Write-Host ('  ' + (T 'flowDnsDiag')) -ForegroundColor $Global:Theme.Header
    $rows = @()
    if ($PingText) {
        $pl = (($PingText -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 1)
        $rows += [PSCustomObject]@{ Item = (T 'flowDnsPing'); Value = $pl }
    } else {
        $rows += [PSCustomObject]@{ Item = (T 'flowDnsPing'); Value = (T 'flowNa') }
    }
    # Firewall DNS servers
    $dnsVal = (T 'flowNa')
    $resp = Invoke-PanApi -FWHost $Device.Host -ApiKey $Device.ApiKey -Params @{ type = 'config'; action = 'get'; xpath = '/config/devices/entry/deviceconfig/system/dns-setting/servers' } -Silent
    if ($resp -and $resp.response.status -eq 'success') {
        $s = $resp.response.result.servers
        if ($s) {
            $p = Get-XmlText $s.primary; $sec = Get-XmlText $s.secondary
            $dnsVal = (@($p, $sec) | Where-Object { $_ }) -join ', '
        }
    }
    $rows += [PSCustomObject]@{ Item = (T 'flowDnsServers'); Value = $dnsVal }
    # DNS proxy stats
    $dstat = (T 'flowNa')
    $dr = Invoke-PanOp -Device $Device -Cmd '<show><dns-proxy><statistics></statistics></dns-proxy></show>' -TimeoutSec 20 -Silent
    if ($dr -and $dr.response.status -eq 'success') {
        $dt = Get-OpText $dr
        if ($dt) {
            $dstat = (($dt -split "`r?`n") | Where-Object { $_.Trim() -and $_ -notmatch '<' } | Select-Object -First 1)
            if (-not $dstat) { $dstat = (T 'flowNa') }
        }
    }
    $rows += [PSCustomObject]@{ Item = (T 'flowDnsProxy'); Value = $dstat }
    # DNS security events
    $threatCount = 0
    $tr = Test-PanQuery -Device $Device -LogType 'threat' -Query "(misc contains $Domain) and (receive_time geq '$Since')" -Limit 200
    if ($tr.Ok) { $threatCount = $tr.Entries.Count }
    $rows += [PSCustomObject]@{ Item = (T 'flowDnsThreat'); Value = ((T 'o2dEvents') -f $threatCount) }
    Out-ColorTable -Objects $rows -Columns @('Item', 'Value')
    Write-Host ''
    Write-WARN (T 'flowDnsBugHint')
}


function Get-FlowSessionRows {
    param($Device, [string]$Src, [string]$Dst)
    $filter = ''
    if ($Src) { $filter += "<source>$Src</source>" }
    if ($Dst) { $filter += "<destination>$Dst</destination>" }
    $cmd = if ($filter) { "<show><session><all><filter>$filter</filter></all></session></show>" } else { '<show><session><all></all></session></show>' }
    $resp = Invoke-PanOp -Device $Device -Cmd $cmd -TimeoutSec 20 -Silent
    if (-not $resp -or $resp.response.status -ne 'success') { return @() }
    $entries = Get-FirstEntryList $resp.response.result
    return @($entries | ForEach-Object {
            [PSCustomObject]@{
                Application = (Get-XmlText $_.application)
                Source      = (Get-XmlText $_.source)
                'Sport'     = (Get-XmlText $_.sport)
                Destination = (Get-XmlText $_.destination)
                'Dport'     = (Get-XmlText $_.dport)
                Proto       = (Get-XmlText $_.proto)
                State       = (Get-XmlText $_.state)
                'In'        = (Get-XmlText $_.'inbound_if')
                'Out'       = (Get-XmlText $_.'outbound_if')
                'NatSrc'    = (Get-XmlText $_.'natsrc')
                'NatDst'    = (Get-XmlText $_.'natdst')
            }
        })
}

function Write-FlowSection {
    param([string]$Title, $Objects, [string[]]$Columns, [hashtable]$ColorMap)
    $arr = @($Objects)
    Write-Host ''
    Write-Host ('  ' + $Title) -ForegroundColor $Global:Theme.Header
    if ($arr.Count -eq 0) { Write-Host ('    ' + (T 'flowNa')) -ForegroundColor $Global:Theme.Muted; return }
    Out-ColorTable -Objects $arr -Columns $Columns -ColorMap $ColorMap
}

function Get-PacketDrops {
    param($Device, [string]$Filter = 'all')
    $resp = Invoke-PanOp -Device $Device -Cmd '<show><counter><global><filter><severity>drop</severity></filter></global></counter></show>' -Silent
    if (-not $resp -or $resp.response.status -ne 'success') { return @() }
    $rows = @(Parse-CounterGlobal -Text (Get-OpText $resp))
    if ($rows.Count -eq 0) {
        $entries = Get-FirstEntryList $resp.response.result
        if ($entries.Count -gt 0) {
            $rows = @($entries | ForEach-Object {
                    $nm = [string]$_.name
                    if (-not $nm) { $nm = Get-XmlText $_.'counter-name' }
                    $vl = [string]$_.value
                    if (-not $vl) { $vl = Get-XmlText $_.value }
                    $vnum = 0L
                    if ($vl -match '^\d+$') { $vnum = [long]$vl }
                    [PSCustomObject]@{ Name = $nm; Value = $vnum; Rate = $null; Severity = ''; Category = '' }
                })
        }
    }
    if ($Filter -ne 'all') {
        $pat = switch ($Filter) {
            'tcp' { 'tcp' }
            'udp' { 'udp' }
            'frag' { 'frag' }
            'resource' { 'resource|out_of|no_mem|alloc|oom|exhaust|buffer|descriptor' }
            default { '' }
        }
        if ($pat) { $rows = @($rows | Where-Object { $_.Name -match $pat }) }
    }
    return $rows
}

function Get-ObservedFlows {
    param($Device, [string]$Src, [string]$Dst, [string]$Since, [string]$DstClause, [switch]$DoExport)
    $q = "(receive_time geq '$Since')"
    if ($Src) { $q += " and (addr.src in $Src)" }
    if ($DstClause) { $q += " and ($DstClause)" }
    $r = Test-PanQuery -Device $Device -LogType 'traffic' -Query $q -Limit 1000
    if (-not $r.Ok) { return @() }
    $objs = @($r.Entries | ForEach-Object { ConvertFrom-PanLogEntry $_ })
    $groups = @($objs | Where-Object { $_.dport } | Group-Object { "$(Get-XmlText $_.application)|$(Get-XmlText $_.dport)" })
    $rows = foreach ($g in $groups) {
        $first = $g.Group[0]
        $acts = (@($g.Group | Group-Object action | ForEach-Object { $_.Name }) -join '/')
        [PSCustomObject]@{
            Application = (Get-XmlText $first.application)
            Dport       = (Get-XmlText $first.dport)
            Events      = $g.Count
            Action      = $acts
            Rule        = (Get-XmlText $first.rule)
        }
    }
    return @($rows | Sort-Object Events -Descending | Select-Object -First 25)
}

function Get-PolicyForFlows {
    param($Device, [string]$Src, [string]$Dst, $Flows, [int]$MaxN = 5, [string]$Protocol = '6')
    $rows = @()
    foreach ($f in @($Flows | Select-Object -First $MaxN)) {
        $port = [string]$f.Dport
        if ($port -notmatch '^\d+$') { continue }
        $resp = Test-PolicyMatch -Device $Device -Src $Src -Dst $Dst -Port $port -App ([string]$f.Application) -Protocol $Protocol
        $txt = ''
        if ($resp) {
            $txt = ((Get-OpText $resp) -split "`r?`n" | Where-Object { $_.Trim() -and $_ -notmatch '^(?i)\s*name\b|^-+\s' } | Select-Object -First 1)
        }
        $rows += [PSCustomObject]@{
            'App/Port' = ("{0}/{1}" -f $f.Application, $port)
            Rule       = if ($txt) { $txt } else { (T 'flowNa') }
        }
    }
    return @($rows)
}

function Show-ConnectivityProbes {
    param($Device, [string]$Dst)
    $rows = @()
    $pr = Invoke-PanOp -Device $Device -Cmd "<ping><host>$Dst</host><count>3</count></ping>" -TimeoutSec 30 -Silent
    if ($pr -and $pr.response.status -eq 'success') {
        $pt = Get-OpText $pr
        $line = (($pt -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -Last 2) -join '  '
        $rows += [PSCustomObject]@{ Probe = (T 'flowPing'); Result = $line }
    } else {
        $rows += [PSCustomObject]@{ Probe = (T 'flowPing'); Result = (T 'flowNa') }
    }
    $tr = Invoke-PanOp -Device $Device -Cmd "<traceroute><host>$Dst</host><count>1</count></traceroute>" -TimeoutSec 40 -Silent
    if ($tr -and $tr.response.status -eq 'success') {
        $tt = Get-OpText $tr
        $hops = @(($tt -split "`r?`n") | Where-Object { $_.Trim() }).Count
        $rows += [PSCustomObject]@{ Probe = (T 'flowTraceroute'); Result = ($hops.ToString() + ' lines') }
    } else {
        $rows += [PSCustomObject]@{ Probe = (T 'flowTraceroute'); Result = (T 'flowNa') }
    }
    return @($rows)
}

function Show-FlowInvestigation {
    param($Device, [string]$Src, [string]$Dst, [string]$Port, [string]$App, [string]$Protocol = '6', [string]$Last = '24h', [string]$DropsFilter = 'all', [switch]$DoExport)
    if (-not $Src -or -not $Dst) { Write-WARN (T 'o2dNeedSrcDst'); return @() }
    $since = Resolve-Since $Last
    $isIp = $Dst -match '^\d{1,3}(\.\d{1,3}){3}$'
    $isDomain = (-not $isIp) -and ($Dst -match '[A-Za-z]')
    $dstIp = if ($isIp) { $Dst } else { '' }

    Write-SectionHeader (T 'flowTitle')
    Write-INFO ((T 'o2dLine') -f $Src, $Dst, $(if ($Port) { $Port } else { '*' }), $(if ($App) { $App } else { '*' }))

    $resolutions = @(); $resSource = ''; $pingText = ''; $unresolved = $false
    if ($isDomain) {
        $res = Resolve-TargetIps -Device $Device -Domain $Dst -Last $Last
        $resolutions = @($res.Ips); $resSource = $res.Source; $pingText = $res.Ping
        if ($resolutions.Count -gt 0) { $dstIp = $resolutions[0] } else { $unresolved = $true }
    }
    $ipList = @($resolutions | Select-Object -Unique)
    if ($ipList.Count -eq 0 -and $dstIp) { $ipList = @($dstIp) }
    $dstClause = (@($ipList | ForEach-Object { "(addr.dst in $_)" }) -join ' or ')

    $hasPort = ($Port -match '^\d+$' -and [int]$Port -ge 1 -and [int]$Port -le 65535)
    $policyText = ''
    if ($hasPort -and $dstIp) {
        $resp = Test-PolicyMatch -Device $Device -Src $Src -Dst $dstIp -Port $Port -App $App -Protocol $Protocol
        if ($resp) { $policyText = Get-OpText $resp }
    }

    $sessions = @()
    if ($dstIp) { $sessions = @(Get-FlowSessionRows -Device $Device -Src $Src -Dst $dstIp) }

    $observedFlows = @(); $policyFlows = @(); $connProbes = @()
    if (-not $hasPort) {
        if ($dstClause) { $observedFlows = @(Get-ObservedFlows -Device $Device -Src $Src -Dst $Dst -Since $since -DstClause $dstClause) }
        if ($observedFlows.Count -gt 0 -and $dstIp) { $policyFlows = @(Get-PolicyForFlows -Device $Device -Src $Src -Dst $dstIp -Flows $observedFlows -MaxN 5 -Protocol $Protocol) }
        $connProbes = @(Show-ConnectivityProbes -Device $Device -Dst $Dst)
        if ($Global:Interactive -and $observedFlows.Count -eq 0 -and $dstIp) {
            $pp = Prompt-Input (T 'flowAskPort')
            if ($pp -match '^\d+$' -and [int]$pp -ge 1 -and [int]$pp -le 65535) {
                $resp = Test-PolicyMatch -Device $Device -Src $Src -Dst $dstIp -Port $pp -App $App -Protocol $Protocol
                if ($resp) { $policyText = Get-OpText $resp }
            }
        }
    }

    $trafficObjs = @()
    if ($dstClause) {
        $tq = "(receive_time geq '$since') and (addr.src in $Src) and ($dstClause)"
        if ($hasPort) { $tq += " and (port.dst eq $Port)" }
        if ($App) { $tq += " and (app eq $App)" }
        $tr = Test-PanQuery -Device $Device -LogType 'traffic' -Query $tq -Limit 500
        if ($tr.Ok) { $trafficObjs = @($tr.Entries | ForEach-Object { ConvertFrom-PanLogEntry $_ }) }
    }

    $threatObjs = @()
    $hq = "(receive_time geq '$since') and (addr.src in $Src)"
    if ($isDomain) { $hq += " and (misc contains $Dst)" } elseif ($dstClause) { $hq += " and ($dstClause)" }
    $th = Test-PanQuery -Device $Device -LogType 'threat' -Query $hq -Limit 500
    if ($th.Ok) { $threatObjs = @($th.Entries | ForEach-Object { ConvertFrom-PanLogEntry $_ }) }

    $urlObjs = @(); $testUrlLine = ''
    if ($isDomain) {
        $ur = Test-PanQuery -Device $Device -LogType 'url' -Query "(receive_time geq '$since') and (misc contains $Dst)" -Limit 500
        if ($ur.Ok) { $urlObjs = @($ur.Entries | ForEach-Object { ConvertFrom-PanLogEntry $_ }) }
        $tu = Test-UrlFiltering -Device $Device -DomainOrUrl $Dst
        if ($tu -and $tu.response.status -eq 'success') { $testUrlLine = if ($tu.response.result -is [System.Xml.XmlElement]) { $tu.response.result.InnerText } else { [string]$tu.response.result } }
    }

    # Strict client-side filter for domain: keep only events containing the domain or with dst in resolved IPs
    if ($isDomain) {
        $esc = [regex]::Escape($Dst)
        $keep = {
            param($o)
            if ((@($o.PSObject.Properties.Value) -match $esc).Count -gt 0) { return $true }
            if ($ipList -contains [string]$o.dst) { return $true }
            return $false
        }
        $trafficObjs = @($trafficObjs | Where-Object { & $keep $_ })
        $threatObjs = @($threatObjs | Where-Object { & $keep $_ })
        $urlObjs = @($urlObjs | Where-Object { & $keep $_ })
    }

    $routeText = ''
    if ($dstIp) { $routeText = [string](Test-FibLookup -Device $Device -Ip $dstIp) }

    $tfirst = @($trafficObjs | Select-Object -First 1)
    $fromZone = if ($tfirst.Count -gt 0) { Get-XmlText $tfirst[0].from } else { '' }
    $toZone = if ($tfirst.Count -gt 0) { Get-XmlText $tfirst[0].to } else { '' }
    $ruleAct = if ($tfirst.Count -gt 0) { (Get-XmlText $tfirst[0].rule) + ' / ' + (Get-XmlText $tfirst[0].action) } else { '' }
    $nat = ''
    if ($tfirst.Count -gt 0 -and ((Get-XmlText $tfirst[0].natsrc) -or (Get-XmlText $tfirst[0].natdst))) { $nat = (Get-XmlText $tfirst[0].natsrc) + ' -> ' + (Get-XmlText $tfirst[0].natdst) }
    $routeLine = ''
    if ($routeText) {
        foreach ($l in ($routeText -split "`r?`n")) { if ($l -match '(?i)egress|interface|next-?hop|nexthop') { $routeLine = $l.Trim(); break } }
        if (-not $routeLine) { $routeLine = (($routeText -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 1) }
    }
    $inIface = if ($sessions.Count -gt 0) { $sessions[0].'In' } else { '' }
    $outIface = if ($sessions.Count -gt 0) { $sessions[0].'Out' } else { '' }

    $policySummary = ''
    if ($policyText) {
        $policySummary = (($policyText -split "`r?`n" | Where-Object { $_.Trim() -and $_ -notmatch '^(?i)\s*name\b|^-+\s' } | Select-Object -First 1))
    } elseif ($policyFlows.Count -gt 0) {
        $policySummary = (@($policyFlows | ForEach-Object { $_.'App/Port' + '=' + $_.Rule }) -join '; ')
    }
    $connSummary = (@($connProbes | ForEach-Object { $_.Probe + ': ' + $_.Result }) -join '  |  ')

    $path = @(
        [PSCustomObject]@{ Hop = (T 'flowHopOrigin'); Detail = ($Src + $(if ($fromZone) { "  ($fromZone " + $(if ($inIface) { $inIface + ')' } else { ')' }) } else { '' })) }
        [PSCustomObject]@{ Hop = (T 'flowHopPolicy'); Detail = $(if ($policySummary) { $policySummary } elseif ($ruleAct) { $ruleAct } else { (T 'flowNa') }) }
        [PSCustomObject]@{ Hop = (T 'flowHopNat'); Detail = $(if ($nat) { $nat } else { (T 'flowNa') }) }
        [PSCustomObject]@{ Hop = (T 'flowHopRoute'); Detail = $(if ($routeLine) { $routeLine } else { (T 'flowNa') }) }
        [PSCustomObject]@{ Hop = (T 'flowHopDest'); Detail = ($Dst + $(if ($toZone) { "  ($toZone " + $(if ($outIface) { $outIface + ')' } else { ')' }) } else { '' })) }
        [PSCustomObject]@{ Hop = (T 'flowHopResolve'); Detail = $(if ($resolutions.Count -gt 0) { ($resolutions -join ', ') + $(if ($resSource) { "  ($resSource)" } else { '' }) } else { (T 'flowNa') }) }
        [PSCustomObject]@{ Hop = (T 'flowHopUrl'); Detail = $(if ($testUrlLine) { $testUrlLine } else { (T 'flowNa') }) }
    )
    if ($connProbes.Count -gt 0) {
        $path += [PSCustomObject]@{ Hop = (T 'flowHopConn'); Detail = $connSummary }
    }
    Write-Host ''
    Write-Host ('  ' + (T 'flowPath')) -ForegroundColor $Global:Theme.Title
    Out-ColorTable -Objects $path -Columns @('Hop', 'Detail')

    if ($policyText) {
        Write-Host ''
        Write-Host ('  ' + (T 'flowPolicySec')) -ForegroundColor $Global:Theme.Header
        foreach ($l in ($policyText -split "`r?`n")) { if ($l.Trim()) { Write-Host ('    ' + $l.Trim()) -ForegroundColor $Global:Theme.Info } }
    }

    Write-FlowSection -Title (T 'flowObservedFlows') -Objects $observedFlows -Columns @('Application', 'Dport', 'Events', 'Action', 'Rule') -ColorMap @{ 'Action' = { param($v) Get-StatusColor $v } }
    Write-FlowSection -Title (T 'flowPolicyPerFlow') -Objects $policyFlows -Columns @('App/Port', 'Rule')
    Write-FlowSection -Title (T 'flowConnProbes') -Objects $connProbes -Columns @('Probe', 'Result')

    Write-FlowSection -Title (T 'flowSessionsSec') -Objects $sessions -Columns @('Application', 'Source', 'Sport', 'Destination', 'Dport', 'Proto', 'State', 'In', 'Out', 'NatSrc', 'NatDst') -ColorMap @{ 'State' = { param($v) Get-StatusColor $v } }
    Write-FlowSection -Title (T 'flowTrafficSec') -Objects $trafficObjs -Columns @('receive_time', 'src', 'dst', 'application', 'dport', 'action', 'rule', 'from', 'to', 'natsrc', 'natdst') -ColorMap @{ 'action' = { param($v) Get-StatusColor $v } }
    if ($isDomain) {
        Write-FlowSection -Title ((T 'flowUrlSec') + ' (URL)') -Objects $urlObjs -Columns @('receive_time', 'src', 'dst', 'misc', 'category', 'action') -ColorMap @{ 'action' = { param($v) Get-StatusColor $v } }
    }
    Write-FlowSection -Title ((T 'flowUrlSec') + ' (DNS/Threat)') -Objects $threatObjs -Columns @('receive_time', 'src', 'dst', 'subtype', 'severity', 'threatid', 'misc', 'action') -ColorMap @{ 'action' = { param($v) Get-StatusColor $v }; 'severity' = { param($v) Get-SeverityColor $v } }

    $drops = @(Get-PacketDrops -Device $Device -Filter $DropsFilter | Where-Object { [long]$_.Value -ne 0 } | Sort-Object { [long]$_.Value } -Descending | Select-Object -First 10 |
            ForEach-Object {
                [PSCustomObject]@{
                    Category    = $_.Category
                    Counter     = $_.Name
                    Value       = ([long]$_.Value).ToString('N0', [System.Globalization.CultureInfo]::InvariantCulture)
                    Description = (Get-DropDescription $_.Name)
                    Raw         = [string]$_.Raw
                }
            })
    Write-FlowSection -Title ((T 'flowDropsSec') + $(if ($DropsFilter -ne 'all') { "  [$DropsFilter]" } else { '' })) -Objects $drops -Columns @('Category', 'Counter', 'Value', 'Description', 'Raw') -ColorMap @{ 'Value' = { param($v) $Global:Theme.Bad } }

    if ($unresolved) {
        Write-Host ''
        Write-WARN ((T 'flowNotResolved') -f $Dst)
        Show-DnsDiagnosis -Device $Device -Domain $Dst -PingText $pingText -Since $since
    }

    if ($DoExport -or $Export) {
        $all = @($sessions + $trafficObjs + $urlObjs + $threatObjs + $observedFlows)
        Export-Results -Objects $all -BaseName 'pan-flow-investigation' -Format $Format -OutDir $Global:OutputDir
    }
    return @($sessions + $trafficObjs + $urlObjs + $threatObjs)
}

function Get-UserMapping {
    param($Device, [string]$Ip)
    if (-not $Ip) { return '' }
    $resp = Invoke-PanOp -Device $Device -Cmd "<show><user><ip-user-mapping><ip>$Ip</ip></ip-user-mapping></user></show>" -TimeoutSec 20 -Silent
    if ($resp -and $resp.response.status -eq 'success') {
        foreach ($ln in ((Get-OpText $resp) -split "`r?`n")) {
            if ($ln -match [regex]::Escape($Ip)) {
                $t = @($ln.Trim() -split '\s+')
                if ($t.Count -ge 3 -and $t[2] -notmatch '^\d') { return $t[2] }
                if ($t.Count -ge 2 -and $t[-1] -notmatch '^\d') { return $t[-1] }
            }
        }
    }
    return ''
}

function Get-UserDir {
    param($Row, [string]$Ip)
    $s = Get-XmlText $Row.src; $d = Get-XmlText $Row.dst
    if ($s -eq $Ip -and $d -eq $Ip) { return (T 'userDirLocal') }
    if ($s -eq $Ip) { return (T 'userDirOut') }
    if ($d -eq $Ip) { return (T 'userDirIn') }
    return ''
}

function Get-UserActivityData {
    param($Device, [string]$Src, [string]$Since, [int]$Limit = 500)
    $Ip = $Src
    $fetch = {
        param([string]$LogType)
        $res = @()
        foreach ($clause in @("(addr.src in $Ip)", "(addr.dst in $Ip)")) {
            $r = Test-PanQuery -Device $Device -LogType $LogType -Query "(receive_time geq '$Since') and $clause" -Limit $Limit
            if ($r.Ok) { $res += @($r.Entries | ForEach-Object { ConvertFrom-PanLogEntry $_ }) }
        }
        $seen = @{}; $u = @()
        foreach ($e in $res) {
            $k = (Get-XmlText $e.receive_time) + '|' + (Get-XmlText $e.src) + '|' + (Get-XmlText $e.dst) + '|' + (Get-XmlText $e.dport) + '|' + (Get-XmlText $e.sessionid) + '|' + (Get-XmlText $e.misc) + '|' + (Get-XmlText $e.action)
            if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $u += $e }
        }
        return @($u)
    }
    $traffic = @(& $fetch 'traffic')
    $threat = @(& $fetch 'threat')
    $url = @(& $fetch 'url')

    $dirIn = (T 'userDirIn')
    $rules = @($traffic | Where-Object { (Get-XmlText $_.rule) } |
        Group-Object { (Get-XmlText $_.rule) + '||' + (Get-XmlText $_.action) + '||' + (Get-UserDir $_ $Ip) } |
        Sort-Object Count -Descending | Select-Object -First 12 |
        ForEach-Object { $t = $_.Name -split '\|\|'; [PSCustomObject]@{ Rule = $t[0]; Action = $t[1]; Dir = $t[2]; Hits = $_.Count } })
    $dests = @($traffic | Where-Object { $_.src -or $_.dst } |
        Group-Object { $d = Get-UserDir $_ $Ip; $p = if ($d -eq $dirIn) { Get-XmlText $_.src } else { Get-XmlText $_.dst }; $p + '||' + $d } |
        Sort-Object Count -Descending | Select-Object -First 12 |
        ForEach-Object { $t = $_.Name -split '\|\|'; [PSCustomObject]@{ Peer = $t[0]; Dir = $t[1]; Hits = $_.Count } })
    $apps = @($traffic | Where-Object { $_.application -or $_.app } |
        Group-Object { $a = Get-XmlText $_.application; if (-not $a) { $a = Get-XmlText $_.app }; $a + '||' + (Get-UserDir $_ $Ip) } |
        Sort-Object Count -Descending | Select-Object -First 12 |
        ForEach-Object { $t = $_.Name -split '\|\|'; [PSCustomObject]@{ App = $t[0]; Dir = $t[1]; Hits = $_.Count } })
    $cats = @($url | Where-Object { $_.category } |
        Group-Object { (Get-XmlText $_.category) + '||' + (Get-UserDir $_ $Ip) } |
        Sort-Object Count -Descending | Select-Object -First 12 |
        ForEach-Object { $t = $_.Name -split '\|\|'; [PSCustomObject]@{ Category = $t[0]; Dir = $t[1]; Hits = $_.Count } })

    $blocks = @()
    foreach ($e in $traffic) { if ((Get-XmlText $e.action) -match '(?i)deny|drop|reset|block') { $d = Get-UserDir $e $Ip; $p = if ($d -eq $dirIn) { Get-XmlText $e.src } else { Get-XmlText $e.dst }; $blocks += [PSCustomObject]@{ Time = (Get-XmlText $e.receive_time); Type = 'traffic'; Dir = $d; Peer = $p; Dport = (Get-XmlText $e.dport); App = (Get-XmlText $e.application); Action = (Get-XmlText $e.action); Rule = (Get-XmlText $e.rule) } } }
    foreach ($e in $threat) { if ((Get-XmlText $e.action) -match '(?i)block|drop|deny|reset|sinkhole') { $d = Get-UserDir $e $Ip; $p = if ($d -eq $dirIn) { Get-XmlText $e.src } else { Get-XmlText $e.dst }; $blocks += [PSCustomObject]@{ Time = (Get-XmlText $e.receive_time); Type = 'threat'; Dir = $d; Peer = $p; Dport = (Get-XmlText $e.dport); App = (Get-XmlText $e.threatid); Action = (Get-XmlText $e.action); Rule = (Get-XmlText $e.subtype) } } }
    foreach ($e in $url) { if ((Get-XmlText $e.action) -match '(?i)block|deny|drop|reset') { $d = Get-UserDir $e $Ip; $p = if ($d -eq $dirIn) { Get-XmlText $e.src } else { Get-XmlText $e.dst }; $blocks += [PSCustomObject]@{ Time = (Get-XmlText $e.receive_time); Type = 'url'; Dir = $d; Peer = $p; Dport = ''; App = (Get-XmlText $e.category); Action = (Get-XmlText $e.action); Rule = '' } } }
    $blocks = @($blocks | Sort-Object Time -Descending | Select-Object -First 20)

    $threats = @($threat | Sort-Object { Get-XmlText $_.receive_time } -Descending | Select-Object -First 15 |
            ForEach-Object { [PSCustomObject]@{ receive_time = (Get-XmlText $_.receive_time); Dir = (Get-UserDir $_ $Ip); src = (Get-XmlText $_.src); dst = (Get-XmlText $_.dst); threatid = (Get-XmlText $_.threatid); subtype = (Get-XmlText $_.subtype); severity = (Get-XmlText $_.severity); misc = (Get-XmlText $_.misc); action = (Get-XmlText $_.action) } })

    $sessions = @()
    foreach ($pair in @(@{ s = $Ip; d = ''; dir = (T 'userDirOut') }, @{ s = ''; d = $Ip; dir = (T 'userDirIn') })) {
        foreach ($se in @(Get-FlowSessionRows -Device $Device -Src $pair.s -Dst $pair.d)) {
            $sessions += [PSCustomObject]@{
                Application = $se.Application; Source = $se.Source; Sport = $se.'Sport'; Destination = $se.Destination
                Dport = $se.'Dport'; Proto = $se.Proto; State = $se.State; Dir = $pair.dir; In = $se.'In'; Out = $se.'Out'
            }
        }
    }

    return [PSCustomObject]@{
        Rules = $rules; Destinations = $dests; Apps = $apps; Categories = $cats
        Blocks = $blocks; Threats = $threats; Sessions = $sessions
        TrafficCount = $traffic.Count; ThreatCount = $threat.Count; UrlCount = $url.Count
    }
}

function Write-UserActivityFrame {
    param($Device, [string]$Src, [string]$User, $Data, [int]$Interval, [bool]$Paused, [string]$Last)
    Write-Host ''
    Write-Host ('  ' + (T 'userActTitle') + '  ' + $Src + $(if ($User) { '  (' + $User + ')' } else { '' })) -ForegroundColor $Global:Theme.Title
    $hdr = '  ' + (Get-Date -Format 'HH:mm:ss') + '   ' + ((T 'cpuRefresh') -f $Interval) + '   ' + (T 'userWindow') + ': ' + $Last
    if ($Paused) { $hdr += '   [' + (T 'cpuPaused') + ']' }
    Write-Host $hdr -ForegroundColor $Global:Theme.Muted
    Write-FlowSection -Title (T 'userSecRules') -Objects $Data.Rules -Columns @('Rule', 'Action', 'Dir', 'Hits') -ColorMap @{ 'Action' = { param($v) Get-StatusColor $v } }
    Write-FlowSection -Title (T 'userSecDests') -Objects $Data.Destinations -Columns @('Peer', 'Dir', 'Hits')
    Write-FlowSection -Title (T 'userSecBlocks') -Objects $Data.Blocks -Columns @('Time', 'Type', 'Dir', 'Peer', 'Dport', 'App', 'Action', 'Rule') -ColorMap @{ 'Action' = { param($v) Get-StatusColor $v } }
    Write-FlowSection -Title (T 'userSecApps') -Objects $Data.Apps -Columns @('App', 'Dir', 'Hits')
    Write-FlowSection -Title (T 'userSecCats') -Objects $Data.Categories -Columns @('Category', 'Dir', 'Hits')
    Write-FlowSection -Title (T 'userSecSessions') -Objects $Data.Sessions -Columns @('Application', 'Source', 'Sport', 'Destination', 'Dport', 'Proto', 'State', 'Dir', 'In', 'Out') -ColorMap @{ 'State' = { param($v) Get-StatusColor $v } }
    Write-FlowSection -Title (T 'userSecThreats') -Objects $Data.Threats -Columns @('receive_time', 'Dir', 'src', 'dst', 'threatid', 'subtype', 'severity', 'misc', 'action') -ColorMap @{ 'action' = { param($v) Get-StatusColor $v }; 'severity' = { param($v) Get-SeverityColor $v } }
    Write-Host ''
    Write-Host ('  ' + (T 'userActKeys')) -ForegroundColor $Global:Theme.Highlight
}

function Show-UserActivity {
    param($Device, [string]$Src, [int]$Interval = 5, [int]$Iterations = 0, [string]$Last = '1h')
    if (-not $Src) { Write-WARN (T 'userNeedSrc'); return }
    if ($Interval -lt 2) { $Interval = 2 }
    if ($Interval -gt 60) { $Interval = 60 }
    $paused = $false; $iter = 0; $user = ''
    while ($true) {
        $since = Resolve-Since $Last
        $user = Get-UserMapping -Device $Device -Ip $Src
        $data = Get-UserActivityData -Device $Device -Src $Src -Since $since
        $iter++
        if ($Global:Interactive) { Clear-Host }
        Write-UserActivityFrame -Device $Device -Src $Src -User $user -Data $data -Interval $Interval -Paused $paused -Last $Last
        if ($Iterations -gt 0 -and $iter -ge $Iterations) { break }
        if (-not $Global:Interactive) { break }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        while ($sw.Elapsed.TotalSeconds -lt $Interval) {
            Start-Sleep -Milliseconds 200
            $ka = $false; try { $ka = [Console]::KeyAvailable } catch { $ka = $false }
            $force = $false
            if ($ka) {
                $k = [Console]::ReadKey($true)
                switch ([string]$k.Key) {
                    'Q' { return }
                    'Escape' { return }
                    'P' { $paused = -not $paused; $sw.Restart() }
                    'R' { $force = $true }
                    'Add' { $Interval = [math]::Min(60, $Interval + 1); $sw.Restart() }
                    'OemPlus' { $Interval = [math]::Min(60, $Interval + 1); $sw.Restart() }
                    'Subtract' { $Interval = [math]::Max(2, $Interval - 1); $sw.Restart() }
                    'OemMinus' { $Interval = [math]::Max(2, $Interval - 1); $sw.Restart() }
                }
            }
            if ($force) { break }
            if ($paused) { $sw.Restart(); Start-Sleep -Milliseconds 200 }
        }
    }
}

function Menu-UserActivity {
    param($Device)
    Write-SectionHeader (T 'userActTitle')
    $src = Prompt-Input (T 'userIpPrompt'); if (-not $src) { return }
    $last = Prompt-Input (T 'userWindowPrompt'); if (-not $last) { $last = '1h' }
    Show-UserActivity -Device $Device -Src $src -Interval $Interval -Last $last
}

function Get-ConfigEntries {
    param($Device, [string]$Xpath)
    $resp = Invoke-PanApi -FWHost $Device.Host -ApiKey $Device.ApiKey -Params @{ type = 'config'; action = 'get'; xpath = $Xpath } -Silent
    if ($resp -and $resp.response.status -eq 'success') { return $resp.response.result }
    return $null
}

function Get-ValueColor {
    param([string]$Value)
    $v = ([string]$Value).Trim()
    if ($v -match '(?i)^(yes|true|allow|allowed|enabled|active|up|valid|permit|permitted)$') { return $Global:Theme.Good }
    if ($v -match '(?i)^(no|false|deny|drop|block|blocked|disabled|down|invalid|sinkhole|reset|reject)$') { return $Global:Theme.Bad }
    if ($v -match '(?i)(sinkhole|block|deny|drop|reject)') { return $Global:Theme.Bad }
    if ($v -match '(?i)(allow|permit|alert)') { return $Global:Theme.Good }
    if ($v -match '(?i)(warn|pend|unknown|partial)') { return $Global:Theme.Caution }
    return $Global:Theme.Info
}

function Show-ConfigTree {
    param($Node, [int]$Indent = 0)
    $pad = ' ' * $Indent
    $children = @($Node.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element })
    $members = @($children | Where-Object { $_.Name -eq 'member' })
    if ($members.Count -gt 0) {
        $val = (($members | ForEach-Object { $_.InnerText }) -join ', ')
        Write-Host ($pad + ('{0,-22}' -f 'member')) -NoNewline -ForegroundColor $Global:Theme.Muted
        Write-Host $val -ForegroundColor $Global:Theme.Info
    }
    foreach ($c in @($children | Where-Object { $_.Name -ne 'member' })) {
        $kids = @($c.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element })
        if ($kids.Count -eq 0) {
            $val = $c.InnerText
            Write-Host ($pad + ('{0,-22}' -f $c.Name)) -NoNewline -ForegroundColor $Global:Theme.Muted
            Write-Host $val -ForegroundColor (Get-ValueColor $val)
        } else {
            Write-Host ($pad + '- ' + $c.Name) -ForegroundColor $Global:Theme.Highlight
            Show-ConfigTree -Node $c -Indent ($Indent + 4)
        }
    }
}

function Show-ConfigCards {
    param($Device, [string]$Xpath, [string]$Title)
    Write-SectionHeader $Title
    $result = Get-ConfigEntries -Device $Device -Xpath $Xpath
    if (-not $result) { Write-WARN ((T 'cfgUnavailable') -f $Title); return }
    $entries = $null
    foreach ($c in @($result.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element })) {
        $e = @($c.SelectNodes('./entry'))
        if ($e.Count -gt 0) { $entries = $e; break }
    }
    if (-not $entries -or @($entries).Count -eq 0) {
        $hasKids = @($result.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element }).Count -gt 0
        if ($hasKids) { Show-ConfigTree -Node $result -Indent 4 }
        else { Write-INFO (T 'cfgNoData') }
        return
    }
    foreach ($e in @($entries)) {
        $name = [string]$e.name
        if (-not $name) { $name = (T 'cfgObject') }
        Write-Host ''
        Write-Host ('  ' + [char]0x2500 + [char]0x2500 + ' ' + $name + ' ') -NoNewline -ForegroundColor $Global:Theme.Title
        Write-Host ([string][char]0x2500 * [math]::Max(0, ((Get-ConsoleWidth) - 8 - $name.Length))) -ForegroundColor $Global:Theme.Border
        Show-ConfigTree -Node $e -Indent 4
    }
    Write-Host ''
}

function Show-ConfigXpath {
    param($Device, [string]$Xpath, [string]$Title)
    Write-SectionHeader $Title
    $result = Get-ConfigEntries -Device $Device -Xpath $Xpath
    if (-not $result) { Write-WARN ((T 'cfgUnavailable') -f $Title); return }
    $containers = @($result.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element })
    if ($containers.Count -eq 0) { Write-WARN (T 'cfgNoData'); return }
    $found = $false
    foreach ($node in $containers) {
        $entries = @($node.SelectNodes('./entry'))
        if ($entries.Count -gt 0) {
            $found = $true
            $rows = @($entries | ForEach-Object { ConvertFrom-PanLogEntry $_ })
            $names = @($rows[0].PSObject.Properties.Name)
            $cols = @('name') + @($names | Where-Object { $_ -ne 'name' })
            Out-ColorTable -Objects $rows -Columns $cols
        } else {
            $rows = @(foreach ($c in $node.ChildNodes) {
                    if ($c.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                        [PSCustomObject]@{ Field = $c.Name; Value = $c.InnerText }
                    }
                })
            if ($rows.Count -gt 0) { $found = $true; Out-ColorTable -Objects $rows -Columns @('Field', 'Value') }
        }
    }
    if (-not $found) { Write-INFO (T 'cfgNoData') }
}

function Show-SecurityRuleProfiles {
    param($Device)
    $vsys = Get-VsysName -Device $Device
    Write-SectionHeader (T 'dnsCfgRules')
    $result = Get-ConfigEntries -Device $Device -Xpath "/config/devices/entry/vsys/entry[@name='$vsys']/rulebase/security/rules"
    if (-not $result -or -not $result.rules.entry) { Write-WARN (T 'cfgNoData'); return }
    $rows = foreach ($r in @($result.rules.entry)) {
        $ps = $r.'profile-setting'
        $prof = ''
        if ($ps) {
            $grp = Get-XmlText $ps.group
            if ($grp) { $prof = $grp }
            $members = @($ps.profiles.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element } | ForEach-Object { "$($_.Name)=$($_.InnerText)" })
            if ($members) { $prof = ($prof + ' ' + ($members -join ', ')).Trim() }
        }
        [PSCustomObject]@{
            Rule     = (Get-XmlText $r.name)
            Action   = (Get-XmlText $r.action)
            Profiles = $prof
            From     = ((@($r.from.member) | ForEach-Object { Get-XmlText $_ }) -join ',')
            To       = ((@($r.to.member) | ForEach-Object { Get-XmlText $_ }) -join ',')
            Disabled = (Get-XmlText $r.disabled)
        }
    }
    Out-ColorTable -Objects @($rows) -Columns @('Rule', 'Action', 'Profiles', 'From', 'To', 'Disabled') -ColorMap @{
        'Action'   = { param($v) Get-StatusColor $v }
        'Disabled' = { param($v) if ($v -match '(?i)yes') { $Global:Theme.Caution } else { $Global:Theme.Good } }
    }
}

function Show-DnsConfig {
    param($Device)
    $vsys = Get-VsysName -Device $Device
    $base = "/config/devices/entry/vsys/entry[@name='$vsys']"
    Show-ConfigCards -Device $Device -Xpath "$base/profiles/spyware" -Title (T 'dnsCfgProfiles')
    Show-ConfigCards -Device $Device -Xpath "$base/dns-proxy" -Title (T 'dnsCfgProxy')
    Show-ConfigCards -Device $Device -Xpath "$base/profiles/url-filtering" -Title (T 'dnsCfgUrl')
    Show-SecurityRuleProfiles -Device $Device
    Write-SectionHeader (T 'dnsCfgContent')
    Show-ContentVersions -Device $Device
}

# ============================================================
# POLICY MATCH (experimental)
# ============================================================
function Resolve-Protocol {
    param([string]$Value)
    $v = ([string]$Value).Trim().ToLower()
    switch ($v) {
        '' { return '6' }
        'tcp' { return '6' }
        'udp' { return '17' }
        'icmp' { return '1' }
        'any' { return '0' }
    }
    if ($v -match '^\d+$') {
        $n = [int]$v
        if ($n -ge 0 -and $n -le 255) { return [string]$n }
    }
    Write-WARN ((T 'protoInvalid') -f $Value)
    return '6'
}

function Test-PolicyMatch {
    param($Device, [string]$Src, [string]$Dst, [string]$Port, [string]$App, [string]$Protocol = '6', [string]$FromZone, [string]$ToZone)
    if (-not $Src -or -not $Dst) {
        Write-WARN (T 'policyNeedSrcDst')
        return @()
    }
    $proto = Resolve-Protocol $Protocol
    $dp = 0
    if ($Port -match '^\d+$') { $dp = [int]$Port }
    if ($dp -lt 1 -or $dp -gt 65535) {
        Write-WARN (T 'policyPortRequired')
        return @()
    }
    $cmd = '<test><security-policy-match>'
    if ($FromZone) { $cmd += "<from>$FromZone</from>" }
    if ($ToZone)   { $cmd += "<to>$ToZone</to>" }
    $cmd += "<source>$Src</source><destination>$Dst</destination>"
    $cmd += "<destination-port>$dp</destination-port>"
    if ($App)  { $cmd += "<application>$App</application>" }
    $cmd += "<protocol>$proto</protocol></security-policy-match></test>"
    $resp = Invoke-PanOp -Device $Device -Cmd $cmd -TimeoutSec 30 -Silent
    if (-not $resp) { Write-ERR (T 'policyNoResponse'); return @() }
    if ($resp.response.status -ne 'success') { Write-ERR ((T 'policyError') -f (Format-PanError $resp)); return @() }
    return $resp
}

# ============================================================
# PACKET CAPTURE
# ============================================================
function Invoke-PanExportRequest {
    param($Device, [hashtable]$Params, [string]$OutFile)
    $headers = @{ 'X-PAN-KEY' = $Device.ApiKey }
    $uri = "https://$($Device.Host)/api/"
    if ($OutFile) {
        Invoke-WebRequest -Uri $uri -Method Post -Headers $headers -Body $Params `
            -OutFile $OutFile -SkipCertificateCheck -TimeoutSec 300 -ErrorAction Stop
        return $null
    }
    $r = Invoke-WebRequest -Uri $uri -Method Post -Headers $headers -Body $Params `
        -SkipCertificateCheck -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
    return $r.Content
}

function Get-PcapListing {
    param($Device, [string]$Category, [string]$From, [string]$DlpPassword)
    $params = @{ type = 'export'; category = $Category }
    if ($From) { $params.from = $From }
    if ($DlpPassword) { $params.'dlp-password' = $DlpPassword }
    try {
        $content = Invoke-PanExportRequest -Device $Device -Params $params
        Write-Host $content
    } catch {
        Write-ERR ((T 'pcapListFailed') -f $_.Exception.Message)
    }
}

function Export-PcapFile {
    param($Device, [string]$Category, [string]$From, [string]$OutFile, [string]$DlpPassword)
    $params = @{ type = 'export'; category = $Category }
    if ($From) { $params.from = $From }
    if ($DlpPassword) { $params.'dlp-password' = $DlpPassword }
    if (-not $OutFile) {
        $leaf = if ($From) { Split-Path $From -Leaf } else { "$Category.pcap" }
        $OutFile = Join-Path $Global:OutputDir $leaf
    }
    $dir = Split-Path $OutFile -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    try {
        Invoke-PanExportRequest -Device $Device -Params $params -OutFile $OutFile | Out-Null
        Write-OK ((T 'pcapSaved') -f $OutFile)
        return $OutFile
    } catch {
        Write-ERR ((T 'pcapDownloadFailed') -f $_.Exception.Message)
        return $null
    }
}

function Export-ThreatPcap {
    param($Device, [string]$PcapId, [string]$SessionId, [string]$SearchTime, [string]$DeviceName, [string]$OutFile)
    if (-not $PcapId) { Write-WARN (T 'threatPcapNeedId'); return $null }
    $params = @{ type = 'export'; category = 'threat-pcap'; 'pcap-id' = $PcapId }
    if ($DeviceName) { $params.device_name = $DeviceName }
    if ($SessionId)  { $params.sessionid = $SessionId }
    if ($SearchTime) { $params.'search-time' = $SearchTime }
    if (-not $OutFile) { $OutFile = Join-Path $Global:OutputDir "apcapid$PcapId.pcap" }
    $dir = Split-Path $OutFile -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    try {
        Invoke-PanExportRequest -Device $Device -Params $params -OutFile $OutFile | Out-Null
        Write-OK ((T 'threatPcapSaved') -f $OutFile)
        return $OutFile
    } catch {
        Write-ERR ((T 'threatPcapFailed') -f $_.Exception.Message)
        return $null
    }
}

function Invoke-LiveCapture {
    param($Device, [string]$Src, [string]$Dst, [string]$Port, [int]$Seconds = 15, [string]$OutFile)
    Write-WARN (T 'liveWarn')
    if (-not (Confirm-Experimental)) { return }
    $match = ''
    if ($Src)  { $match += "<match><src>$Src</src></match>" }
    if ($Dst)  { $match += "<match><dst>$Dst</dst></match>" }
    if ($Port) { $match += "<match><dport>$Port</dport></match>" }
    if (-not $match) { Write-WARN (T 'liveNeedMatch'); return }

    $setCmd   = "<debug><dataplane><packet-diag><set><filter>$match</filter></set></packet-diag></dataplane></debug>"
    $onCmd    = '<debug><dataplane><packet-diag><on></on></packet-diag></dataplane></debug>'
    $offCmd   = '<debug><dataplane><packet-diag><off></off></packet-diag></dataplane></debug>'
    $clearCmd = '<debug><dataplane><packet-diag><clear><filter></filter></clear></packet-diag></dataplane></debug>'

    $r1 = Invoke-PanOp -Device $Device -Cmd $setCmd -Silent
    if (-not $r1 -or $r1.response.status -ne 'success') {
        Write-ERR ((T 'liveSetFail') -f (Format-PanError $r1))
        Write-WARN (T 'liveUnsupported')
        return
    }
    $r2 = Invoke-PanOp -Device $Device -Cmd $onCmd -Silent
    if (-not $r2 -or $r2.response.status -ne 'success') {
        Write-ERR ((T 'liveStartFail') -f (Format-PanError $r2))
        Write-WARN (T 'liveUnsupported')
        return
    }
    Write-OK ((T 'liveRunning') -f $Seconds)
    Start-Sleep -Seconds $Seconds
    Invoke-PanOp -Device $Device -Cmd $offCmd -Silent | Out-Null
    Write-INFO (T 'liveDownloading')
    if (-not $OutFile) { $OutFile = Join-Path $Global:OutputDir ("livecapture-{0}.pcap" -f (Get-Date -Format 'yyyyMMdd-HHmmss')) }
    Export-PcapFile -Device $Device -Category 'filters-pcap' -From $null -OutFile $OutFile | Out-Null
    Invoke-PanOp -Device $Device -Cmd $clearCmd -Silent | Out-Null
}

function Confirm-Experimental {
    if (-not $Global:Interactive) { return $true }
    return (Prompt-Confirm (T 'expConfirm'))
}

# ============================================================
# REPORTS
# ============================================================
function Get-PanReport {
    param($Device, [string]$Type, [string]$Name, [string]$Period, [int]$TopN, [int]$MaxWaitSec = 180)
    $params = @{ type = 'report'; reporttype = $Type }
    if ($Name) { $params.reportname = $Name }
    if ($Type -eq 'dynamic') {
        if ($Period) { $params.period = $Period }
        if ($TopN)   { $params.topn = $TopN }
    }
    $resp = Invoke-PanApi -FWHost $Device.Host -ApiKey $Device.ApiKey -Params $params -TimeoutSec 60
    if (-not $resp) { return $null }
    if ($resp.response.status -ne 'success') { Write-ERR ((T 'reportError') -f (Format-PanError $resp)); return $null }
    $job = $resp.response.result.job
    if ($job) { return (Wait-PanJob -Device $Device -JobId $job -Type 'report' -MaxWaitSec $MaxWaitSec) }
    return $resp
}

function Get-ReportNames {
    param($Resp)
    $names = @()
    $xml = $Resp.OuterXml
    foreach ($m in [regex]::Matches($xml, 'reportname="([^"]+)"')) { $names += $m.Groups[1].Value }
    if ($names.Count -eq 0) {
        foreach ($m in [regex]::Matches($xml, '<entry name="([^"]+)"')) { $names += $m.Groups[1].Value }
    }
    return @($names | Sort-Object -Unique)
}

function ConvertFrom-PanReportXml {
    param($Node, [string]$Prefix = '')
    $rows = @()
    foreach ($c in $Node.ChildNodes) {
        if ($c.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
        $label = if ($Prefix) { "$Prefix.$($c.Name)" } else { $c.Name }
        $hasChildEl = @($c.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element }).Count -gt 0
        if ($hasChildEl) { $rows += ConvertFrom-PanReportXml -Node $c -Prefix $label }
        else { $rows += [PSCustomObject]@{ Field = $label; Value = $c.InnerText } }
    }
    return $rows
}

function Show-Report {
    param($Device, [string]$Type, [string]$Name, [string]$Period, [int]$TopN, [switch]$DoExport)
    if (-not $Name) {
        Write-INFO ((T 'reportFetching') -f $Type)
        $resp = Invoke-PanApi -FWHost $Device.Host -ApiKey $Device.ApiKey -Params @{ type = 'report'; reporttype = $Type } -TimeoutSec 30 -Silent
        if (-not $resp) { Write-ERR ((T 'opNoResponse') -f 'report'); return $null }
        $names = Get-ReportNames $resp
        if ($names.Count -gt 0) {
            $rows = @($names | ForEach-Object { [PSCustomObject]@{ Report = $_; Type = $Type } })
            Out-ColorTable -Objects $rows -Columns @('Report', 'Type')
        } else {
            Write-INFO (T 'reportNone')
            Write-Host ('  ' + $resp.OuterXml.Trim())
        }
        return $null
    }
    Write-INFO ((T 'reportRunning') -f $Type, $Name)
    $resp = Get-PanReport -Device $Device -Type $Type -Name $Name -Period $Period -TopN $TopN
    if (-not $resp) { return $null }
    $xml = $resp.OuterXml
    $reportNode = $null
    foreach ($p in @('report', 'report-data')) {
        if ($resp.response.result.$p) { $reportNode = $resp.response.result.$p; break }
    }
    if ($reportNode) {
        $rows = @(ConvertFrom-PanReportXml -Node $reportNode)
        if ($rows.Count -gt 0) { Out-ColorTable -Objects $rows -Columns @('Field', 'Value') }
        else { Write-Host ('  ' + $xml.Trim()) }
    } else {
        Write-Host ('  ' + $xml.Trim())
    }
    if ($DoExport -or $Export) {
        Export-XmlContent -Content $xml -BaseName "pan-report-$Name"
    }
    return $xml
}

# ============================================================
# SYSTEM / HEALTH / NETWORK
# ============================================================
function Show-SystemInfo {
    param($Device)
    $resp = Invoke-PanOp -Device $Device -Cmd '<show><system><info></info></system></show>' -Silent
    if (-not $resp -or $resp.response.status -ne 'success') { Write-ERR ((T 'sysReadFailed') -f (Format-PanError $resp)); return }
    $s = $resp.response.result.system
    $rows = [ordered]@{
        (T 'sysHostname')  = (Get-XmlText $s.hostname)
        (T 'sysModel')     = (Get-XmlText $s.model)
        (T 'sysSerial')    = (Get-XmlText $s.serial)
        (T 'sysVersion')   = (Get-XmlText $s.'sw-version')
        (T 'sysUptime')    = (Get-XmlText $s.uptime)
        (T 'sysMgmtIp')    = (Get-XmlText $s.'ip-address')
        (T 'sysOpMode')    = (Get-XmlText $s.'operational-mode')
        (T 'sysMultiVsys') = (Get-XmlText $s.'multi-vsys')
    }
    Write-Host ''
    foreach ($k in $rows.Keys) {
        Write-Host ('  {0,-20}' -f $k) -NoNewline -ForegroundColor $Global:Theme.Header
        Write-Host $rows[$k] -ForegroundColor $Global:Theme.Info
    }
    Write-Host ''
}

function Show-ContentVersions {
    param($Device)
    $resp = Invoke-PanOp -Device $Device -Cmd '<show><system><info></info></system></show>' -Silent
    if (-not $resp -or $resp.response.status -ne 'success') { Write-ERR ((T 'contentReadFailed') -f (Format-PanError $resp)); return }
    $s = $resp.response.result.system
    $rows = [ordered]@{
        (T 'cAppThreat')  = (Get-XmlText $s.'app-version')
        (T 'cAppRelease') = (Get-XmlText $s.'app-release-date')
        (T 'cAv')         = (Get-XmlText $s.'av-version')
        (T 'cThreat')     = (Get-XmlText $s.'threat-version')
        (T 'cUrl')        = (Get-XmlText $s.'url-filtering-version')
        (T 'cWildfire')   = (Get-XmlText $s.'wildfire-version')
        (T 'cLogdb')      = (Get-XmlText $s.'logdb-version')
        (T 'cDevCert')    = (Get-XmlText $s.'device-certificate-status')
    }
    Write-Host ''
    foreach ($k in $rows.Keys) {
        Write-Host ('  {0,-26}' -f $k) -NoNewline -ForegroundColor $Global:Theme.Header
        Write-Host $rows[$k] -ForegroundColor $Global:Theme.Info
    }
    Write-Host ''
}

function Get-FirstEntryList {
    param($Node)
    if ($null -eq $Node) { return @() }
    if ($Node.entry) { return @($Node.entry) }
    foreach ($c in $Node.ChildNodes) {
        if ($c.NodeType -eq [System.Xml.XmlNodeType]::Element -and $c.entry) { return @($c.entry) }
    }
    return @()
}

function Show-OpResult {
    param($Resp, [string]$Title)
    if (-not $Resp) { Write-ERR ((T 'opNoResponse') -f $Title); return }
    if ($Resp -is [string]) { Write-Host $Resp; return }
    if ($Resp.response.status -ne 'success') { Write-ERR ((T 'opNoResponse') -f "$Title -> $(Format-PanError $Resp)"); return }
    $r = $Resp.response.result
    $entries = Get-FirstEntryList $r
    if ($entries.Count -gt 0) {
        $rows = @($entries | ForEach-Object { ConvertFrom-PanLogEntry $_ })
        $names = @($rows[0].PSObject.Properties.Name)
        Out-ColorTable -Objects $rows -Columns $names
        return
    }
    $kids = @($r.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element })
    if ($kids.Count -gt 0) {
        $rows = @(foreach ($c in $kids) { [PSCustomObject]@{ Field = $c.Name; Value = $c.InnerText } })
        Out-ColorTable -Objects $rows -Columns @('Field', 'Value')
        return
    }
    if ($r.InnerText) { Write-Host ('  ' + $r.InnerText) } else { Write-INFO (T 'noData') }
}

function Show-SimpleOp {
    param($Device, [string]$Cmd, [string]$Title)
    Show-OpResult -Resp (Invoke-PanOp -Device $Device -Cmd $Cmd -Silent) -Title $Title
}

function Show-HaStatus {
    param($Device)
    $resp = Invoke-PanOp -Device $Device -Cmd '<show><high-availability><state></state></high-availability></show>' -Silent
    if (-not $resp -or $resp.response.status -ne 'success') { Write-ERR ((T 'opNoResponse') -f (T 'sysHaItem')); return }
    $r = $resp.response.result
    $group = $r.group
    $rows = @()
    if ($group) {
        foreach ($side in @('local-info', 'peer-info')) {
            $info = $group.$side
            if ($info) {
                $rows += [PSCustomObject]@{
                    Node     = if ($side -eq 'local-info') { (T 'haLocal') } else { (T 'haPeer') }
                    State    = (Get-XmlText $info.state)
                    HaState  = (Get-XmlText $info.'ha-state')
                    Priority = (Get-XmlText $info.priority)
                    MgmtIP   = (Get-XmlText $info.'mgmt-ip')
                    BuildCompat = (Get-XmlText $info.'build-compat')
                }
            }
        }
    }
    if ($rows.Count -gt 0) {
        Out-ColorTable -Objects $rows -Columns @('Node', 'State', 'HaState', 'Priority', 'MgmtIP', 'BuildCompat') -ColorMap @{
            'State'   = { param($v) Get-StatusColor $v }
            'HaState' = { param($v) Get-StatusColor $v }
        }
        return
    }
    Show-SimpleOp -Device $Device -Cmd '<show><high-availability><state></state></high-availability></show>' -Title (T 'sysHaItem')
}

function Show-Licenses {
    param($Device)
    $resp = Invoke-PanOp -Device $Device -Cmd '<request><license><info></info></license></request>' -Silent
    if (-not $resp -or $resp.response.status -ne 'success') { Write-ERR ((T 'opNoResponse') -f (T 'sysLicItem')); return }
    $lic = $resp.response.result.licenses
    if (-not $lic -or -not $lic.entry) { Write-INFO (T 'noData'); return }
    $rows = foreach ($e in @($lic.entry)) {
        $expired = (Get-XmlText $e.expired)
        $exp = (Get-XmlText $e.expires)
        $status = if ($expired -match '(?i)yes') { 'EXPIRED' } elseif ($exp) { 'VALID' } else { 'N/A' }
        [PSCustomObject]@{
            Feature     = (Get-XmlText $e.feature)
            Description = (Get-XmlText $e.description)
            Expires     = $exp
            Status      = $status
        }
    }
    Out-ColorTable -Objects @($rows) -Columns @('Feature', 'Description', 'Expires', 'Status') -ColorMap @{
        'Status' = { param($v) Get-StatusColor $v }
    }
}

function Show-Interfaces {
    param($Device)
    $resp = Invoke-PanOp -Device $Device -Cmd '<show><interface>all</interface></show>' -Silent
    if (-not $resp -or $resp.response.status -ne 'success') { Write-ERR ((T 'opNoResponse') -f (T 'sysIfItem')); return }
    $r = $resp.response.result
    $rows = @()
    foreach ($grp in @('hw', 'ifnet', 'vlan', 'vsi')) {
        $node = $r.$grp
        if ($node -and $node.entry) {
            foreach ($e in @($node.entry)) {
                $rows += [PSCustomObject]@{
                    Interface = (Get-XmlText $e.name)
                    Type      = $grp
                    State     = (Get-XmlText $e.state)
                    Id        = (Get-XmlText $e.id)
                    Zone      = (Get-XmlText $e.zone)
                    Mac       = (Get-XmlText $e.mac)
                }
            }
        }
    }
    if ($rows.Count -eq 0) { Show-SimpleOp -Device $Device -Cmd '<show><interface>all</interface></show>' -Title (T 'sysIfItem'); return }
    Out-ColorTable -Objects $rows -Columns @('Interface', 'Type', 'State', 'Id', 'Zone', 'Mac') -ColorMap @{
        'State' = { param($v) Get-StatusColor $v }
    }
}

function Show-Routes {
    param($Device)
    $resp = Invoke-PanOp -Device $Device -Cmd '<show><routing><route></route></routing></show>' -Silent
    if (-not $resp -or $resp.response.status -ne 'success') { Write-ERR ((T 'opNoResponse') -f (T 'sysRouteItem')); return }
    $r = $resp.response.result
    $entries = Get-FirstEntryList $r
    if ($entries.Count -eq 0) { Show-SimpleOp -Device $Device -Cmd '<show><routing><route></route></routing></show>' -Title (T 'sysRouteItem'); return }
    $rows = foreach ($e in $entries) {
        [PSCustomObject]@{
            Destination = (Get-XmlText $e.destination)
            NextHop     = (Get-XmlText $e.nexthop)
            Interface   = (Get-XmlText $e.interface)
            Metric      = (Get-XmlText $e.metric)
            Flags       = (Get-XmlText $e.flags)
        }
    }
    Out-ColorTable -Objects @($rows) -Columns @('Destination', 'NextHop', 'Interface', 'Metric', 'Flags') -ColorMap @{
        'Flags' = { param($v) if ($v -match 'A') { $Global:Theme.Good } else { $Global:Theme.Neutral } }
    }
}

function Show-Arp {
    param($Device)
    $resp = Invoke-PanOp -Device $Device -Cmd "<show><arp><entry name='all'/></arp></show>" -Silent
    if (-not $resp -or $resp.response.status -ne 'success') { Write-ERR ((T 'opNoResponse') -f (T 'sysArpItem')); return }
    $r = $resp.response.result
    $entries = Get-FirstEntryList $r
    if ($entries.Count -eq 0) { Show-SimpleOp -Device $Device -Cmd "<show><arp><entry name='all'/></arp></show>" -Title (T 'sysArpItem'); return }
    $rows = foreach ($e in $entries) {
        [PSCustomObject]@{
            IP        = (Get-XmlText $e.ip)
            Mac       = (Get-XmlText $e.mac)
            Interface = (Get-XmlText $e.interface)
            Port      = (Get-XmlText $e.port)
            TTL       = (Get-XmlText $e.ttl)
        }
    }
    Out-ColorTable -Objects @($rows) -Columns @('IP', 'Mac', 'Interface', 'Port', 'TTL')
}

function Show-Jobs {
    param($Device)
    $resp = Invoke-PanOp -Device $Device -Cmd '<show><jobs><all></all></jobs></show>' -Silent
    if (-not $resp -or $resp.response.status -ne 'success') { Write-ERR ((T 'opNoResponse') -f (T 'sysJobsItem')); return }
    $jobs = @($resp.response.result.job)
    if ($jobs.Count -eq 0) { Write-INFO (T 'noData'); return }
    $rows = @($jobs | ForEach-Object {
            [PSCustomObject]@{
                id      = (Get-XmlText $_.id)
                start   = (Get-XmlText $_.tenq)
                end     = (Get-XmlText $_.tfin)
                user    = (Get-XmlText $_.user)
                type    = (Get-XmlText $_.type)
                status  = (Get-XmlText $_.status)
                result  = (Get-XmlText $_.result)
                description = (Get-XmlText $_.description)
            }
        } | Sort-Object -Property start -Descending)
    Out-ColorTable -Objects $rows -Columns @('id', 'start', 'end', 'user', 'type', 'status', 'result', 'description') -ColorMap @{
        'result' = { param($v) Get-StatusColor $v }
        'status' = { param($v) Get-StatusColor $v }
    }
}

function Show-JobDetail {
    param($Device, [string]$JobId)
    if (-not $JobId) { return }
    $resp = Invoke-PanOp -Device $Device -Cmd "<show><jobs><id>$JobId</id></jobs></show>" -Silent
    if (-not $resp -or $resp.response.status -ne 'success') { Write-ERR ((T 'opNoResponse') -f "job $JobId"); return }
    $job = $resp.response.result.job
    if (-not $job) { Write-INFO (T 'noData'); return }
    $rows = @(foreach ($c in $job.ChildNodes) {
            if ($c.NodeType -eq [System.Xml.XmlNodeType]::Element) { [PSCustomObject]@{ Field = $c.Name; Value = $c.InnerText } }
        })
    Out-ColorTable -Objects $rows -Columns @('Field', 'Value') -ColorMap @{
        'Value' = { param($v) Get-StatusColor $v }
    }
}

function Show-Sessions {
    param($Device, [string]$Src, [string]$Dst, [string]$App)
    $filter = ''
    if ($Src) { $filter += "<source>$Src</source>" }
    if ($Dst) { $filter += "<destination>$Dst</destination>" }
    if ($App) { $filter += "<application>$App</application>" }
    $cmd = if ($filter) {
        "<show><session><all><filter>$filter</filter></all></session></show>"
    } else {
        '<show><session><all></all></session></show>'
    }
    $resp = Invoke-PanOp -Device $Device -Cmd $cmd -Silent
    if (-not $resp -or $resp.response.status -ne 'success') { Write-ERR ((T 'opNoResponse') -f (T 'sysSessionItem')); return }
    $r = $resp.response.result
    $entries = Get-FirstEntryList $r
    if ($entries.Count -eq 0) { Write-INFO (T 'noData'); return }
    $rows = foreach ($e in $entries) {
        [PSCustomObject]@{
            Application = (Get-XmlText $e.application)
            Source      = (Get-XmlText $e.source)
            Sport       = (Get-XmlText $e.sport)
            Destination = (Get-XmlText $e.destination)
            Dport       = (Get-XmlText $e.dport)
            Proto       = (Get-XmlText $e.proto)
            State       = (Get-XmlText $e.state)
        }
    }
    Out-ColorTable -Objects @($rows) -Columns @('Application', 'Source', 'Sport', 'Destination', 'Dport', 'Proto', 'State') -ColorMap @{
        'State' = { param($v) Get-StatusColor $v }
    }
}

function Show-ConfigSaved {
    param($Device)
    $resp = Invoke-PanOp -Device $Device -Cmd '<show><config><saved></saved></config></show>' -Silent
    if (-not $resp -or $resp.response.status -ne 'success') { Write-ERR ((T 'opNoResponse') -f (T 'sysSavedItem')); return }
    $r = $resp.response.result
    $entries = Get-FirstEntryList $r
    if ($entries.Count -gt 0) {
        $rows = @($entries | ForEach-Object {
                [PSCustomObject]@{
                    Name    = (Get-XmlText $_.name)
                    Created = (Get-XmlText $_.'created')
                    Size    = (Get-XmlText $_.'size')
                }
            })
        Out-ColorTable -Objects $rows -Columns @('Name', 'Created', 'Size')
        return
    }
    if ($r.InnerText -and $r.InnerText.Trim()) {
        foreach ($line in ($r.InnerText -split "`n")) { if ($line.Trim()) { Write-Host ('  ' + $line.Trim()) } }
        return
    }
    Write-INFO (T 'noData')
}

# ============================================================
# CPU / CORES LIVE MONITOR
# ============================================================
function Get-OpText {
    param($Resp)
    if (-not $Resp) { return '' }
    if ($Resp -is [string]) { return $Resp }
    try {
        $r = $Resp.response.result
        if ($r -is [System.Xml.XmlElement]) {
            if ($r.InnerText) { return $r.InnerText }
            return $r.OuterXml
        }
        if ($r) { return [string]$r }
    } catch { }
    return $Resp.OuterXml
}

function Format-Bar {
    param([double]$Pct, [int]$Width = 20)
    $p = [math]::Max(0, [math]::Min(100, $Pct))
    $fill = [int][math]::Round($p / 100 * $Width)
    return ([string][char]0x2588 * $fill) + ([string][char]0x2591 * ($Width - $fill))
}

function Get-PctColor {
    param([double]$Pct)
    if ($Pct -ge 90) { return $Global:Theme.Bad }
    if ($Pct -ge 70) { return $Global:Theme.Caution }
    return $Global:Theme.Good
}

function Parse-SystemResources {
    param([string]$Text)
    $o = [ordered]@{
        Uptime = ''; Load1 = $null; Load5 = $null; Load15 = $null
        Us = $null; Sy = $null; Ni = $null; Id = $null; Wa = $null; Hi = $null; Si = $null; St = $null
        Tasks = ''
        MemTotal = $null; MemFree = $null; MemUsed = $null; MemCache = $null; MemAvail = $null
        SwapTotal = $null; SwapFree = $null; SwapUsed = $null
        Processes = @()
    }
    if (-not $Text) { return [PSCustomObject]$o }
    $lines = $Text -split "`r?`n"
    foreach ($ln in $lines) {
        if ($null -eq $o.Load1 -and $ln -match 'load average:\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)') {
            $o.Load1 = [double]$matches[1]; $o.Load5 = [double]$matches[2]; $o.Load15 = [double]$matches[3]
            if ($ln -match 'up\s+(.+?),\s+\d+\s+user') { $o.Uptime = $matches[1].Trim() }
            continue
        }
        if ($ln -match '^%Cpu\(s\):\s*([\d.]+)\s*us,\s*([\d.]+)\s*sy,\s*([\d.]+)\s*ni,\s*([\d.]+)\s*id,\s*([\d.]+)\s*wa,\s*([\d.]+)\s*hi,\s*([\d.]+)\s*si,\s*([\d.]+)\s*st') {
            $o.Us = [double]$matches[1]; $o.Sy = [double]$matches[2]; $o.Ni = [double]$matches[3]; $o.Id = [double]$matches[4]
            $o.Wa = [double]$matches[5]; $o.Hi = [double]$matches[6]; $o.Si = [double]$matches[7]; $o.St = [double]$matches[8]
            continue
        }
        if ($ln -match '^MiB Mem\s*:\s*([\d.]+)\s*total,\s*([\d.]+)\s*free,\s*([\d.]+)\s*used,\s*([\d.]+)\s*buff/cache') {
            $o.MemTotal = [double]$matches[1]; $o.MemFree = [double]$matches[2]; $o.MemUsed = [double]$matches[3]; $o.MemCache = [double]$matches[4]
            continue
        }
        if ($ln -match '^MiB Swap:\s*([\d.]+)\s*total,\s*([\d.]+)\s*free,\s*([\d.]+)\s*used\.\s*([\d.]+)\s*avail Mem') {
            $o.SwapTotal = [double]$matches[1]; $o.SwapFree = [double]$matches[2]; $o.SwapUsed = [double]$matches[3]; $o.MemAvail = [double]$matches[4]
            continue
        }
        if ($ln -match '^Tasks:\s*(.+)$') { $o.Tasks = $matches[1].Trim(); continue }
    }
    $procs = @()
    $hdr = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^\s*PID\s+USER\s+') { $hdr = $i; break } }
    if ($hdr -ge 0) {
        for ($i = $hdr + 1; $i -lt $lines.Count; $i++) {
            $ln = $lines[$i]
            if ($ln.Trim() -eq '') { break }
            if ($ln -notmatch '^\s*\d+\s+') { break }
            $t = @($ln.Trim() -split '\s+')
            $si = -1
            for ($x = 1; $x -lt [math]::Min(11, $t.Count); $x++) { if ($t[$x] -match '^[A-Z]$') { $si = $x; break } }
            if ($si -lt 0 -or $t.Count -lt ($si + 5)) { continue }
            $cpuTok = $t[$si + 1]; $memTok = $t[$si + 2]
            if ($cpuTok -notmatch '^\d+(\.\d+)?$') { continue }
            if ($memTok -notmatch '^\d+(\.\d+)?$') { continue }
            $cmd = ($t[($si + 4)..($t.Count - 1)] -join ' ')
            $procs += [PSCustomObject]@{ Pid = $t[0]; Cpu = [double]$cpuTok; Mem = [double]$memTok; Command = $cmd }
        }
    }
    $o.Processes = @($procs | Sort-Object Cpu -Descending)
    return [PSCustomObject]$o
}

function Parse-ResourceMonitor {
    param([string]$Text)
    $o = [ordered]@{ Groups = @{}; CoreLatest = @{}; CoreMinute = @{}; Resources = @{} }
    if (-not $Text) { return [PSCustomObject]$o }
    $lines = $Text -split "`r?`n"

    $inGroup = $false
    foreach ($ln in $lines) {
        if ($ln -match 'CPU load sampling by group:') { $inGroup = $true; continue }
        if ($inGroup) {
            if ($ln -match '^\s*([a-z_]+)\s*:\s*(\d+)%') { $o.Groups[$matches[1]] = [int]$matches[2]; continue }
            if ($ln.Trim() -eq '' -and $o.Groups.Count -gt 0) { $inGroup = $false }
        }
    }

    $secStart = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match 'CPU load \(%\) during last \d+ (second|minute|hour)s?:') { $secStart = $i; break }
    }
    if ($secStart -ge 0) {
        $secEnd = $lines.Count
        for ($i = $secStart + 1; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match 'Resource utilization \(%\)|CPU load \(%\) during last \d+ (minute|hour)s?:') { $secEnd = $i; break }
        }
        $j = $secStart + 1
        while ($j -lt $secEnd) {
            if ($lines[$j] -match '^\s*core\s+((?:\d+\s*)+)$') {
                $cores = @($matches[1].Trim() -split '\s+' | ForEach-Object { [int]$_ })
                $j++
                $rows = @()
                while ($j -lt $secEnd -and $lines[$j] -notmatch '^\s*core\s+') {
                    $lt = $lines[$j].Trim()
                    if ($lt -ne '') { $rows += , @($lt -split '\s+') }
                    $j++
                }
                if ($rows.Count -gt 0) {
                    $last = $rows[$rows.Count - 1]
                    for ($ci = 0; $ci -lt $cores.Count -and $ci -lt $last.Count; $ci++) {
                        $v = $last[$ci]
                        $core = $cores[$ci]
                        if ($v -eq '*') { $o.CoreLatest[$core] = $null } else { $o.CoreLatest[$core] = [int]$v }
                    }
                }
            } else { $j++ }
        }
    }

    $mStart = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match 'CPU load \(%\) during last \d+ (minute|hour)s?:') { $mStart = $i; break } }
    if ($mStart -ge 0) {
        $mEnd = $lines.Count
        for ($i = $mStart + 1; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^Resource utilization \(%\)') { $mEnd = $i; break } }
        $j = $mStart + 1
        while ($j -lt $mEnd) {
            if ($lines[$j] -match '^\s*core\s+((?:\d+\s*)+)$') {
                $cores = @($matches[1].Trim() -split '\s+' | ForEach-Object { [int]$_ })
                $j++
                if ($j -lt $mEnd -and $lines[$j] -match 'avg') { $j++ }
                $rows = @()
                while ($j -lt $mEnd -and $lines[$j] -notmatch '^\s*core\s+') {
                    $lt = $lines[$j].Trim()
                    if ($lt -ne '') { $rows += , @($lt -split '\s+') }
                    $j++
                }
                if ($rows.Count -gt 0) {
                    $last = $rows[$rows.Count - 1]
                    for ($ci = 0; $ci -lt $cores.Count; $ci++) {
                        $ai = $ci * 2; $mi = $ai + 1
                        if ($mi -lt $last.Count) {
                            $av = $last[$ai]; $mx = $last[$mi]
                            $o.CoreMinute[$cores[$ci]] = [PSCustomObject]@{
                                Avg = if ($av -eq '*') { $null } else { [int]$av }
                                Max = if ($mx -eq '*') { $null } else { [int]$mx }
                            }
                        }
                    }
                }
            } else { $j++ }
        }
    }

    $want = @('session', 'packet buffer', 'packet descriptor', 'packet descriptor (on-chip)', 'sw tags descriptor')
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*([A-Za-z][A-Za-z0-9 _\-\(\)]*):\s*$') {
            $name = $matches[1].Trim().ToLower()
            if ($want -notcontains $name) { continue }
            $k = $i + 1; $lastVal = $null; $any = $false
            while ($k -lt $lines.Count) {
                $lt = $lines[$k].Trim()
                if ($lt -eq '' -or $lt -notmatch '^[\d*\s]+$') { break }
                foreach ($tk in @($lt -split '\s+')) { if ($tk -match '^\d+$') { $lastVal = [int]$tk; $any = $true } }
                $k++
            }
            if ($any) { $o.Resources[$name] = $lastVal }
        }
    }
    return [PSCustomObject]$o
}

$script:RmCmd = $null
function Get-ResourceMonitorData {
    param($Device)
    $candidates = @(
        '<show><running><resource-monitor><second></second></resource-monitor></running></show>',
        '<show><running><resource-monitor><second><last>60</last></second></resource-monitor></running></show>',
        '<show><running><resource-monitor><minute></minute></resource-monitor></running></show>',
        '<show><running><resource-monitor></resource-monitor></running></show>'
    )
    if ($script:RmCmd) { $candidates = @($script:RmCmd) + @($candidates | Where-Object { $_ -ne $script:RmCmd }) }
    $lastErr = ''
    foreach ($cmd in $candidates) {
        $resp = Invoke-PanOp -Device $Device -Cmd $cmd -TimeoutSec 20 -Silent
        if (-not $resp) { $lastErr = (T 'noResponse'); continue }
        if ($resp.response.status -ne 'success') { $lastErr = (Format-PanError $resp); continue }
        $parsed = Parse-ResourceMonitor -Text (Get-OpText $resp)
        if ($parsed.CoreLatest.Count -gt 0) {
            $script:RmCmd = $cmd
            return [PSCustomObject]@{ Parsed = $parsed; Error = '' }
        }
        $lastErr = (T 'cpuRmEmpty')
    }
    return [PSCustomObject]@{ Parsed = (Parse-ResourceMonitor -Text ''); Error = $lastErr }
}

$script:CoreTaskMap = $null
$script:CoreTaskTime = [datetime]::MinValue
function Get-CoreTaskMap {
    param($Device, [int]$MaxAgeSec = 60)
    if ($script:CoreTaskMap -and ((Get-Date) - $script:CoreTaskTime).TotalSeconds -lt $MaxAgeSec) { return $script:CoreTaskMap }
    $map = @{}
    $resp = Invoke-PanOp -Device $Device -Cmd '<show><statistics></statistics></show>' -TimeoutSec 30 -Silent
    if ($resp -and $resp.response.status -eq 'success') {
        foreach ($ln in ((Get-OpText $resp) -split "`r?`n")) {
            if ($ln -match '^\s*task\s+(\d+)\s*\(pid:\s*(\d+)\)\s*(.+?)\s*$') {
                $map[[int]$matches[1]] = [PSCustomObject]@{ Pid = $matches[2]; Groups = $matches[3].Trim() }
            }
        }
    }
    $script:CoreTaskMap = $map
    $script:CoreTaskTime = Get-Date
    return $map
}

function Write-CpuFrame {
    param($Device, $Sys, $Rm, [int]$Interval, [string]$View, [string]$Mode, [bool]$Paused, [string]$RmError, $CoreTask)
    $ver = if ($Device.PanOSVersion) { "  ($($Device.PanOSVersion))" } else { '' }
    Write-Host ''
    Write-Host ('  ' + (T 'cpuTitle') + '  ' + $Device.Name + $ver) -ForegroundColor $Global:Theme.Title
    $stamp = (Get-Date -Format 'HH:mm:ss')
    $hdr = '  ' + $stamp + '   ' + ((T 'cpuRefresh') -f $Interval)
    if ($Paused) { $hdr += '   [' + (T 'cpuPaused') + ']' }
    Write-Host $hdr -ForegroundColor $Global:Theme.Muted

    if (-not $Sys -or ($null -eq $Sys.Load1 -and $null -eq $Sys.MemTotal)) {
        Write-Host ''
        Write-WARN (T 'cpuNoData')
        return
    }

    Write-Host ''
    Write-Host ('  ' + (T 'cpuUptime') + ': ' + $Sys.Uptime + '    ' + (T 'cpuLoad') + ': ' + $Sys.Load1 + ' | ' + $Sys.Load5 + ' | ' + $Sys.Load15) -ForegroundColor $Global:Theme.Info

    if ($null -ne $Sys.Id) {
        $used = [math]::Round(100 - $Sys.Id, 1)
        Write-Host ''
        Write-Host ('  ' + (T 'cpuMgmt')) -ForegroundColor $Global:Theme.Header
        Write-Host ('    ' + (Format-Bar $used 24) + ('  {0,5}%' -f $used) + ('    us {0}  sy {1}  wa {2}  hi {3}  id {4}' -f $Sys.Us, $Sys.Sy, $Sys.Wa, $Sys.Hi, $Sys.Id)) -ForegroundColor (Get-PctColor $used)
    }

    if ($null -ne $Sys.MemTotal -and $Sys.MemTotal -gt 0) {
        $memPct = [math]::Round($Sys.MemUsed / $Sys.MemTotal * 100, 1)
        $gbT = [math]::Round($Sys.MemTotal / 1024, 1); $gbU = [math]::Round($Sys.MemUsed / 1024, 1); $gbA = [math]::Round($Sys.MemAvail / 1024, 1)
        Write-Host ''
        Write-Host ('  ' + (T 'cpuMem') + '  ' + (Format-Bar $memPct 24) + ('  {0,5}%' -f $memPct) + ('    {0}/{1} GB  ' -f $gbU, $gbT) + (T 'cpuAvailable') + (' {0} GB' -f $gbA)) -ForegroundColor (Get-PctColor $memPct)
        if ($null -ne $Sys.SwapTotal -and $Sys.SwapTotal -gt 0) {
            $swPct = [math]::Round($Sys.SwapUsed / $Sys.SwapTotal * 100, 1)
            Write-Host ('  ' + (T 'cpuSwap') + '  ' + (Format-Bar $swPct 24) + ('  {0,5}%' -f $swPct)) -ForegroundColor (Get-PctColor $swPct)
        }
    }

    if ($Rm -and $Rm.CoreLatest.Count -gt 0) {
        $full = ($View -eq 'detail')
        $cores = @($Rm.CoreLatest.Keys | Sort-Object)
        $useMin = ($Mode -eq 'min') -and ($Rm.CoreMinute.Count -gt 0)
        $satThreshold = 80
        $sat = @($Rm.CoreLatest.GetEnumerator() | Where-Object { $null -ne $_.Value -and $_.Value -ge $satThreshold } | Sort-Object Value -Descending)
        Write-Host ''
        Write-Host ('  ' + (T 'cpuPerCore') + $(if ($useMin) { '  [1m avg/max]' } else { '  [1s]' })) -ForegroundColor $Global:Theme.Header
        if ($sat.Count -gt 0) {
            $list = ($sat | Select-Object -First 8 | ForEach-Object { 'c{0} {1}%' -f $_.Key, $_.Value }) -join '  '
            Write-Host ('    ' + ((T 'cpuSaturated') -f $sat.Count) + ': ' + $list) -ForegroundColor $Global:Theme.Caution
        }
        if ($full) {
            $w = Get-ConsoleWidth
            $cellW = if ($useMin) { 16 } else { 11 }
            $perRow = [math]::Max(1, [math]::Floor(($w - 4) / $cellW))
            if ($perRow -gt 8) { $perRow = 8 }
            for ($i = 0; $i -lt $cores.Count; $i++) {
                $c = $cores[$i]
                if ($useMin) {
                    $mm = $Rm.CoreMinute[$c]
                    if ($null -eq $mm -or ($null -eq $mm.Avg -and $null -eq $mm.Max)) {
                        $text = ('c{0} --' -f $c); $col = $Global:Theme.Muted
                    } else {
                        $text = ('c{0} {1}/{2}' -f $c, $mm.Avg, $mm.Max)
                        $col = Get-PctColor ([double]$mm.Max)
                    }
                } else {
                    $v = $Rm.CoreLatest[$c]
                    $text = if ($null -eq $v) { ('c{0} --' -f $c) } else { ('c{0} {1,3}%{2}' -f $c, $v, $(if ($v -ge 80) { '!' } else { '' })) }
                    $col = if ($null -eq $v) { $Global:Theme.Muted } else { Get-PctColor $v }
                }
                Write-Host ('    ' + $text.PadRight($cellW)) -NoNewline -ForegroundColor $col
                if ((($i + 1) % $perRow) -eq 0) { Write-Host '' }
            }
            if (($cores.Count % $perRow) -ne 0) { Write-Host '' }
            if ($CoreTask -and $CoreTask.Count -gt 0) {
                Write-Host ''
                Write-Host ('  ' + (T 'cpuCoreTask')) -ForegroundColor $Global:Theme.Header
                foreach ($c in $cores) {
                    if (-not $CoreTask.ContainsKey($c)) { continue }
                    $v = $Rm.CoreLatest[$c]
                    $pct = if ($null -eq $v) { '  --' } else { ('{0,3}%' -f $v) }
                    $col = if ($null -eq $v) { $Global:Theme.Muted } else { Get-PctColor $v }
                    Write-Host ('    c{0,-3} {1}  ' -f $c, $pct) -NoNewline -ForegroundColor $col
                    Write-Host $CoreTask[$c].Groups -ForegroundColor $Global:Theme.Info
                }
            }
        } else {
            if ($useMin) {
                $pairs = @($Rm.CoreMinute.GetEnumerator() | Where-Object { $null -ne $_.Value.Max })
                if ($pairs.Count -gt 0) {
                    $avg = [math]::Round(($pairs | ForEach-Object { $_.Value.Avg } | Measure-Object -Average).Average, 1)
                    $max = ($pairs | ForEach-Object { $_.Value.Max } | Measure-Object -Maximum).Maximum
                    Write-Host ('    avg ' + $avg + '%   max ' + $max + '%   (1 min)') -ForegroundColor $Global:Theme.Info
                }
            } else {
                $pairs = @($Rm.CoreLatest.GetEnumerator() | Where-Object { $null -ne $_.Value })
                if ($pairs.Count -gt 0) {
                    $avg = [math]::Round(($pairs | Measure-Object -Property Value -Average).Average, 1)
                    $max = ($pairs | Measure-Object -Property Value -Maximum).Maximum
                    $top = @($pairs | Sort-Object Value -Descending | Select-Object -First 8 | ForEach-Object { 'c{0} {1}%' -f $_.Key, $_.Value })
                    Write-Host ('    avg ' + $avg + '%   max ' + $max + '%   ' + ($top -join '  ')) -ForegroundColor $Global:Theme.Info
                }
            }
        }
    } else {
        Write-Host ''
        if ($RmError) { Write-WARN ((T 'cpuRmError') -f $RmError) }
        else { Write-INFO (T 'cpuRmEmpty') }
    }

    if ($Rm -and $Rm.Groups.Count -gt 0) {
        Write-Host ''
        Write-Host ('  ' + (T 'cpuGroups')) -ForegroundColor $Global:Theme.Header
        $g = @($Rm.Groups.Keys)
        $cellW = 24
        $perRow = [math]::Max(1, [math]::Floor(((Get-ConsoleWidth) - 4) / $cellW))
        for ($i = 0; $i -lt $g.Count; $i++) {
            $name = $g[$i]; $val = $Rm.Groups[$name]
            Write-Host ('    ' + ('{0} {1}%' -f $name, $val).PadRight($cellW)) -NoNewline -ForegroundColor (Get-PctColor $val)
            if ((($i + 1) % $perRow) -eq 0) { Write-Host '' }
        }
        if (($g.Count % $perRow) -ne 0) { Write-Host '' }
    }

    if ($Rm -and $Rm.Resources.Count -gt 0) {
        Write-Host ''
        Write-Host ('  ' + (T 'cpuResources')) -ForegroundColor $Global:Theme.Header
        foreach ($name in @('session', 'packet buffer', 'packet descriptor', 'packet descriptor (on-chip)', 'sw tags descriptor')) {
            if (-not $Rm.Resources.ContainsKey($name)) { continue }
            $val = $Rm.Resources[$name]
            Write-Host ('    ' + ('{0,-20}' -f $name) + (Format-Bar $val 16) + ('  {0,5}%' -f $val)) -ForegroundColor (Get-PctColor $val)
        }
    }

    if ($Sys.Processes.Count -gt 0) {
        Write-Host ''
        Write-Host ('  ' + (T 'cpuTopProc')) -ForegroundColor $Global:Theme.Header
        Write-Host ('    ' + ('{0,-22}' -f 'COMMAND') + ('{0,8}' -f 'CPU%') + ('{0,8}' -f 'MEM%')) -ForegroundColor $Global:Theme.Muted
        foreach ($p in @($Sys.Processes | Select-Object -First 6)) {
            Write-Host ('    ' + ('{0,-22}' -f $p.Command) + ('{0,8}' -f $p.Cpu) + ('{0,8}' -f $p.Mem)) -ForegroundColor (Get-PctColor ([math]::Min(100, $p.Cpu)))
        }
    }

    Write-Host ''
    Write-Host ('  ' + (T 'cpuKeys')) -ForegroundColor $Global:Theme.Highlight
}

function Show-CpuMonitor {
    param($Device, [int]$Interval = 5, [int]$Iterations = 0, [switch]$Summary)
    if ($Interval -lt 1) { $Interval = 1 }
    if ($Interval -gt 10) { $Interval = 10 }
    $paused = $false
    $view = if ($Summary) { 'summary' } else { 'detail' }
    $mode = 'sec'
    $iter = 0
    $sys = $null; $rm = $null
    while ($true) {
        $sysResp = Invoke-PanOp -Device $Device -Cmd '<show><system><resources></resources></system></show>' -TimeoutSec 15 -Silent
        $sys = Parse-SystemResources -Text (Get-OpText $sysResp)
        $rmData = Get-ResourceMonitorData -Device $Device
        $rm = $rmData.Parsed
        $rmError = $rmData.Error
        $coreTask = Get-CoreTaskMap -Device $Device
        $iter++

        if ($Global:Interactive) { Clear-Host }
        Write-CpuFrame -Device $Device -Sys $sys -Rm $rm -Interval $Interval -View $view -Mode $mode -Paused $paused -RmError $rmError -CoreTask $coreTask

        if ($Iterations -gt 0 -and $iter -ge $Iterations) { break }
        if (-not $Global:Interactive) { break }

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        while ($sw.Elapsed.TotalSeconds -lt $Interval) {
            Start-Sleep -Milliseconds 200
            $keyAvail = $false
            try { $keyAvail = [Console]::KeyAvailable } catch { $keyAvail = $false }
            $forceRefresh = $false
            if ($keyAvail) {
                $k = [Console]::ReadKey($true)
                switch ([string]$k.Key) {
                    'Q' { return }
                    'Escape' { return }
                    'P' { $paused = -not $paused; $sw.Restart() }
                    'R' { $forceRefresh = $true }
                    'Add' { $Interval = [math]::Min(10, $Interval + 1); $sw.Restart() }
                    'OemPlus' { $Interval = [math]::Min(10, $Interval + 1); $sw.Restart() }
                    'Subtract' { $Interval = [math]::Max(1, $Interval - 1); $sw.Restart() }
                    'OemMinus' { $Interval = [math]::Max(1, $Interval - 1); $sw.Restart() }
                    'D' { $view = if ($view -eq 'detail') { 'summary' } else { 'detail' } }
                    'H' { $mode = if ($mode -eq 'sec') { 'min' } else { 'sec' } }
                    'G' { $script:CoreTaskTime = [datetime]::MinValue; $forceRefresh = $true }
                }
            }
            if ($forceRefresh) { break }
            if ($paused) { $sw.Restart() ; Start-Sleep -Milliseconds 200 }
        }
    }
}

# ============================================================
# PACKET DROPS / COUNTERS
# ============================================================
function Parse-CounterGlobal {
    param([string]$Text)
    $rows = @()
    if (-not $Text) { return $rows }
    $catWords = @('flow', 'pktproc', 'session', 'resource', 'fabric', 'ctr', 'ipproto', 'tcp', 'udp', 'dns', 'ssl', 'tls', 'appid', 'decrypt', 'url', 'threat', 'packet', 'hw', 'jumbo', 'nat', 'route', 'vpn', 'userid', 'doh', 'dot')
    foreach ($ln in ($Text -split "`r?`n")) {
        if ($ln -notmatch '\d') { continue }
        $t = @($ln.Trim() -split '\s+')
        if ($t.Count -lt 2) { continue }
        $name = $null
        foreach ($tok in $t) { if ($tok -match '^[A-Za-z][\w\.\-/]*_[\w\.\-/]*$') { $name = $tok; break } }
        if (-not $name) { if ($t[0] -match '^[A-Za-z][\w\.\-/:]*$') { $name = $t[0] } else { continue } }
        $val = $null; $rate = $null
        for ($i = 1; $i -lt $t.Count; $i++) {
            if ($t[$i] -match '^\d+$') { if ($null -eq $val) { $val = [long]$t[$i] } elseif ($null -eq $rate) { $rate = [long]$t[$i] } }
        }
        if ($null -eq $val) { continue }
        $sev = ''; $cat = ''
        foreach ($w in $t) { if ($w -match '^(?i)(drop|allow|info|warn|error|fatal|critical|debug)$') { $sev = $w.ToLower() } }
        foreach ($w in $t) { if ($catWords -contains $w.ToLower()) { $cat = $w.ToLower(); break } }
        if (-not $cat) { foreach ($w in $t) { if ($w -cmatch '^[A-Z]{2,}$' -and $w -ne $name) { $cat = $w; break } } }
        $rows += [PSCustomObject]@{ Name = $name; Value = $val; Rate = $rate; Severity = $sev; Category = $cat; Raw = $ln.Trim() }
    }
    return $rows
}

function Get-DropDescription {
    param([string]$Name)
    $n = ([string]$Name).ToLower()
    if ($n -match 'frag') { return (T 'dropDescFrag') }
    if ($n -match 'offload|fpga|pon') { return (T 'dropDescOffload') }
    if ($n -match 'tcp') { return (T 'dropDescTcp') }
    if ($n -match 'udp') { return (T 'dropDescUdp') }
    if ($n -match 'dns|doh|dot') { return (T 'dropDescDns') }
    if ($n -match 'out_of|no_mem|oom|resource|exhaust|buffer|descriptor|alloc') { return (T 'dropDescResource') }
    if ($n -match 'policy|deny|denied') { return (T 'dropDescPolicy') }
    if ($n -match 'decrypt|ssl|tls') { return (T 'dropDescDecrypt') }
    if ($n -match 'session') { return (T 'dropDescSession') }
    if ($n -match 'icmp|land|ttl|ttl_|ip_|ipv4|ipv6|fragment') { return (T 'dropDescIp') }
    return (T 'dropDescOther')
}

function Show-PacketDrops {
    param($Device, [string]$Filter = 'all', [switch]$DoExport)
    Write-SectionHeader ((T 'dropsTitle') + $(if ($Filter -ne 'all') { "  [$Filter]" } else { '' }))
    $rows = @(Get-PacketDrops -Device $Device -Filter $Filter)
    if ($rows.Count -eq 0) { Write-INFO (T 'noData'); return @() }
    $nonzero = @($rows | Where-Object { [long]$_.Value -ne 0 })
    Write-INFO ((T 'dropsTotal') -f $rows.Count)
    if ($nonzero.Count -eq 0) {
        Write-Host ('  ' + (T 'dropsNone')) -ForegroundColor $Global:Theme.Good
    } else {
        $disp = @($nonzero | ForEach-Object {
                [PSCustomObject]@{
                    Category    = $_.Category
                    Counter     = $_.Name
                    Value       = ([long]$_.Value).ToString('N0', [System.Globalization.CultureInfo]::InvariantCulture)
                    Description = (Get-DropDescription $_.Name)
                    Raw         = [string]$_.Raw
                }
            } | Sort-Object @{ Expression = { $_.Category } }, @{ Expression = { [long](($_.Value) -replace '[^\d]', '') }; Descending = $true })
        Out-ColorTable -Objects $disp -Columns @('Category', 'Counter', 'Value', 'Description', 'Raw') -ColorMap @{
            'Value' = { param($v) if ((Get-NumberStr $v) -ne '' -and [long](Get-NumberStr $v) -gt 0) { $Global:Theme.Bad } else { $Global:Theme.Good } }
        }
        $total = [long](@($nonzero | Measure-Object -Property Value -Sum).Sum)
        Write-INFO ((T 'dropsSummary') -f $nonzero.Count, $total)
    }
    if ($DoExport -or $Export) { Export-Results -Objects $rows -BaseName 'pan-drops' -Format $Format -OutDir $Global:OutputDir }
    return $rows
}

function Get-NumberStr {
    param($V)
    if ($null -eq $V) { return '' }
    return (([string]$V) -replace '[^\d]', '')
}

function Format-Bytes {
    param($V)
    $s = Get-NumberStr $V
    if ($s -eq '') { return '' }
    $n = [double]$s
    $units = @('B', 'KB', 'MB', 'GB', 'TB', 'PB')
    $i = 0
    while ($n -ge 1024 -and $i -lt ($units.Count - 1)) { $n = $n / 1024; $i++ }
    if ($i -eq 0) { return ('{0:N0} {1}' -f $n, $units[$i]) }
    return ('{0:N2} {1}' -f $n, $units[$i])
}

function Format-Num {
    param($V)
    $s = Get-NumberStr $V
    if ($s -eq '') { return '' }
    return ([long]$s).ToString('N0', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Test-Positive {
    param($V)
    $s = Get-NumberStr $V
    return ($s -ne '' -and [long]$s -gt 0)
}

function Show-InterfaceCounters {
    param($Device, [switch]$DoExport)
    Write-SectionHeader (T 'ifCountersTitle')
    $resp = Invoke-PanOp -Device $Device -Cmd '<show><counter><interface>all</interface></counter></show>'
    if (-not $resp -or $resp.response.status -ne 'success') { Write-ERR ((T 'opNoResponse') -f (T 'ifCountersTitle')); return @() }
    $entries = Get-FirstEntryList $resp.response.result
    if ($entries.Count -eq 0) {
        Show-OpResult -Resp $resp -Title (T 'ifCountersTitle')
        return @()
    }
    $rows = @()
    foreach ($e in $entries) {
        $if = Get-XmlText $e.name
        if (-not $if) { $if = Get-XmlText $e.interface }
        if (-not $if) { continue }
        $errRaw = Get-XmlText $e.ierrors
        $dropRaw = Get-XmlText $e.idrops
        $rows += [PSCustomObject]@{
            Interface = $if
            'In'      = Format-Bytes (Get-XmlText $e.ibytes)
            'Out'     = Format-Bytes (Get-XmlText $e.obytes)
            'InPkts'  = Format-Num (Get-XmlText $e.ipackets)
            'OutPkts' = Format-Num (Get-XmlText $e.opackets)
            Errors    = Format-Num $errRaw
            Drops     = Format-Num $dropRaw
            _err      = [long]$(if ((Get-NumberStr $errRaw) -ne '') { Get-NumberStr $errRaw } else { 0 })
            _drop     = [long]$(if ((Get-NumberStr $dropRaw) -ne '') { Get-NumberStr $dropRaw } else { 0 })
        }
    }
    if ($rows.Count -eq 0) { Write-INFO (T 'noData'); return @() }
    $rows = @($rows | Sort-Object Interface)
    Out-ColorTable -Objects $rows -Columns @('Interface', 'In', 'Out', 'InPkts', 'OutPkts', 'Errors', 'Drops') -ColorMap @{
        'Errors' = { param($v) if (Test-Positive $v) { $Global:Theme.Caution } else { $Global:Theme.Good } }
        'Drops'  = { param($v) if (Test-Positive $v) { $Global:Theme.Bad } else { $Global:Theme.Good } }
    }
    $totDrop = [long](@($rows | Measure-Object -Property _drop -Sum).Sum)
    $totErr = [long](@($rows | Measure-Object -Property _err -Sum).Sum)
    $ifWithDrop = @($rows | Where-Object { $_._drop -gt 0 }).Count
    Write-INFO ((T 'ifcSummary') -f $rows.Count, $ifWithDrop, $totErr, $totDrop)
    if ($DoExport -or $Export) { Export-Results -Objects $rows -BaseName 'pan-if-counters' -Format $Format -OutDir $Global:OutputDir }
    return $rows
}

function Menu-Drops {
    param($Device)
    do {
        Write-Banner
        $groups = @(
            @{ Label = (T 'grpDrops'); Items = @(
                    @{ Key = '1'; Label = (T 'dropsAll') }
                    @{ Key = '2'; Label = (T 'dropsTcp') }
                    @{ Key = '3'; Label = (T 'dropsUdp') }
                    @{ Key = '4'; Label = (T 'dropsFrag') }
                    @{ Key = '5'; Label = (T 'dropsResource') }
                    @{ Key = '6'; Label = (T 'ifCountersTitle') }
                )
            }
        )
        Write-Menu -Title (T 'dropsTitle') -Groups $groups -BackLabel (T 'back')
        switch (Prompt-Input (T 'selectOption')) {
            '1' { $o = Show-PacketDrops -Device $Device -Filter 'all'; Invoke-ExportPrompt -Objects $o -BaseName 'pan-drops'; Pause-Enter }
            '2' { $o = Show-PacketDrops -Device $Device -Filter 'tcp'; Invoke-ExportPrompt -Objects $o -BaseName 'pan-drops-tcp'; Pause-Enter }
            '3' { $o = Show-PacketDrops -Device $Device -Filter 'udp'; Invoke-ExportPrompt -Objects $o -BaseName 'pan-drops-udp'; Pause-Enter }
            '4' { $o = Show-PacketDrops -Device $Device -Filter 'frag'; Invoke-ExportPrompt -Objects $o -BaseName 'pan-drops-frag'; Pause-Enter }
            '5' { $o = Show-PacketDrops -Device $Device -Filter 'resource'; Invoke-ExportPrompt -Objects $o -BaseName 'pan-drops-resource'; Pause-Enter }
            '6' { $o = Show-InterfaceCounters -Device $Device; Invoke-ExportPrompt -Objects $o -BaseName 'pan-if-counters'; Pause-Enter }
            '0' { return }
            default { Write-WARN (T 'invalidOption'); Start-Sleep -Seconds 1 }
        }
    } while ($true)
}

# ============================================================
# COMMIT / CONFIG HISTORY
# ============================================================
function Get-PanCommitHistory {
    param($Device, [int]$Limit = 200, [switch]$DoExport)
    Write-INFO (T 'histCommits')
    $resp = Invoke-PanOp -Device $Device -Cmd '<show><jobs><all></all></jobs></show>' -Silent
    if (-not $resp -or $resp.response.status -ne 'success') {
        Write-ERR ((T 'opNoResponse') -f (T 'histCommits'))
        return @()
    }
    $jobs = @()
    $j = $resp.response.result.job
    if ($j) { $jobs = @($j) }
    $commit = @($jobs | Where-Object { (Get-XmlText $_.type) -match '(?i)commit' })
    if ($commit.Count -eq 0) { Write-WARN (T 'noCommits'); return @() }
    $objs = @($commit | ForEach-Object {
            [PSCustomObject]@{
                id          = (Get-XmlText $_.id)
                start       = (Get-XmlText $_.tenq)
                end         = (Get-XmlText $_.tfin)
                user        = (Get-XmlText $_.user)
                type        = (Get-XmlText $_.type)
                status      = (Get-XmlText $_.status)
                result      = (Get-XmlText $_.result)
                description = (Get-XmlText $_.description)
                warnings    = (@($_.warnings.line | ForEach-Object { Get-XmlText $_ }) -join '; ')
            }
        })
    $objs = @($objs | Sort-Object -Property start -Descending | Select-Object -First $Limit)
    Write-INFO ((T 'entriesReturned') -f $objs.Count)
    Out-ColorTable -Objects $objs -Columns @('id', 'start', 'end', 'user', 'type', 'status', 'result', 'description') -ColorMap @{
        'result' = { param($v) Get-StatusColor $v }
        'status' = { param($v) Get-StatusColor $v }
    }
    if ($DoExport -or $Export) {
        Export-Results -Objects $objs -BaseName 'pan-commit-history' -Format $Format -OutDir $Global:OutputDir
    }
    return $objs
}

function Get-PanConfigChanges {
    param($Device, [string]$Last = '7d', [string]$Admin, [string]$Cmd, [string]$Path, [int]$Limit = 200, [switch]$DoExport)
    $since = Resolve-Since $Last
    $q = "(receive_time geq '$since')"
    if ($Admin) { $q += " and (admin eq '$Admin')" }
    if ($Cmd)   { $q += " and (cmd eq '$Cmd')" }
    if ($Path)  { $q += " and (path contains $Path)" }
    Write-INFO ((T 'query') -f $q)
    $entries = Get-PanLog -Device $Device -LogType 'config' -Query $q -Limit $Limit
    $objs = @($entries | ForEach-Object { ConvertFrom-PanLogEntry $_ })
    Write-INFO ((T 'entriesReturned') -f $objs.Count)
    Out-ColorTable -Objects $objs -Columns @('receive_time', 'admin', 'vsys', 'cmd', 'path', 'before-change-detail', 'after-change-detail', 'result') -ColorMap @{
        'result' = { param($v) Get-StatusColor $v }
        'cmd'    = { param($v) if ($v -match '(?i)delete') { $Global:Theme.Bad } elseif ($v -match '(?i)commit') { $Global:Theme.Good } else { $Global:Theme.Caution } }
    }
    if ($DoExport -or $Export) {
        Export-Results -Objects $objs -BaseName 'pan-config-changes' -Format $Format -OutDir $Global:OutputDir
    }
    return $objs
}

function Show-PendingChanges {
    param($Device)
    Write-INFO (T 'histPending')
    $resp = Invoke-PanOp -Device $Device -Cmd '<show><config><list><change-summary/></list></config></show>' -Silent
    if (-not $resp) { Write-ERR ((T 'opNoResponse') -f 'change-summary'); return }
    if ($resp -is [string]) { Write-Host ('  ' + $resp.Trim()); return }
    if ($resp.response.status -ne 'success') { Write-ERR (Format-PanError $resp); return }
    $r = $resp.response.result
    if ($r.msg) {
        $lines = @($r.msg.line)
        if ($lines.Count -gt 0) {
            foreach ($l in $lines) { Write-Host ('  ' + (Get-XmlText $l)) -ForegroundColor $Global:Theme.Info }
            return
        }
        Write-Host ('  ' + (Get-XmlText $r.msg)) -ForegroundColor $Global:Theme.Info
        return
    }
    $kids = @($r.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element })
    if ($kids.Count -gt 0) {
        $rows = @($kids | ForEach-Object { [PSCustomObject]@{ Field = $_.Name; Value = $_.InnerText } })
        Out-ColorTable -Objects $rows -Columns @('Field', 'Value')
        return
    }
    Write-INFO (T 'noData')
}

function Show-RunningCandidateDiff {
    param($Device, [switch]$DoExport)
    Write-INFO (T 'histDiff')
    $run = Invoke-PanApi -FWHost $Device.Host -ApiKey $Device.ApiKey -Params @{ type = 'config'; action = 'show' } -TimeoutSec 60 -Silent
    $cand = Invoke-PanApi -FWHost $Device.Host -ApiKey $Device.ApiKey -Params @{ type = 'config'; action = 'get' } -TimeoutSec 60 -Silent
    if (-not $run -or -not $cand) { Write-ERR (T 'diffFailed'); return @() }
    $runLines = @(($run.OuterXml -split "`r?`n"))
    $candLines = @(($cand.OuterXml -split "`r?`n"))
    $diff = @(Compare-Object -ReferenceObject $runLines -DifferenceObject $candLines)
    if ($diff.Count -eq 0) { Write-OK (T 'diffNone'); return @() }
    Write-INFO ((T 'diffLines') -f $diff.Count)
    $objs = @($diff | ForEach-Object {
            $prefix = if ($_.SideIndicator -eq '=>') { '+ ' } else { '- ' }
            Write-Host ($prefix + $_.InputObject)
            [PSCustomObject]@{ change = $_.SideIndicator; text = $_.InputObject }
        })
    if ($DoExport -or $Export) {
        Export-Results -Objects $objs -BaseName 'pan-config-diff' -Format $Format -OutDir $Global:OutputDir
    }
    return $objs
}

function Menu-History {
    param($Device)
    do {
        Write-Banner
        $groups = @(
            @{ Items = @(
                    @{ Key = '1'; Label = (T 'histCommits') }, @{ Key = '2'; Label = (T 'histChanges') }
                    @{ Key = '3'; Label = (T 'histPending') }, @{ Key = '4'; Label = (T 'histDiff') }
                    @{ Key = '5'; Label = (T 'histJobDetail') }, @{ Key = '6'; Label = (T 'histSaved') }
                )
            }
        )
        Write-Menu -Title "$(T 'histTitle') - $($Device.Name)" -Groups $groups -BackLabel (T 'back')
        Write-INFO (T 'histNote')
        switch (Prompt-Input (T 'selectOption')) {
            '1' {
                $objs = Get-PanCommitHistory -Device $Device -Limit 200
                Invoke-ExportPrompt -Objects $objs -BaseName 'pan-commit-history'
                Pause-Enter
            }
            '2' {
                $admin = Prompt-Input (T 'histAdminPrompt')
                $cmd = Prompt-Input (T 'histCmdPrompt')
                $path = Prompt-Input (T 'histPathPrompt')
                $last = Prompt-Input (T 'histWindowPrompt'); if (-not $last) { $last = '7d' }
                $limit = Prompt-Input (T 'histLimitPrompt'); if (-not $limit) { $limit = '200' }
                $objs = Get-PanConfigChanges -Device $Device -Last $last -Admin $admin -Cmd $cmd -Path $path -Limit ([int]$limit)
                Invoke-ExportPrompt -Objects $objs -BaseName 'pan-config-changes'
                Pause-Enter
            }
            '3' { Show-PendingChanges -Device $Device; Pause-Enter }
            '4' {
                $objs = Show-RunningCandidateDiff -Device $Device
                Invoke-ExportPrompt -Objects $objs -BaseName 'pan-config-diff'
                Pause-Enter
            }
            '5' {
                $jid = Prompt-Input (T 'histJobIdPrompt')
                Show-JobDetail -Device $Device -JobId $jid
                Pause-Enter
            }
            '6' { Show-ConfigSaved -Device $Device; Pause-Enter }
            '0' { return }
            default { Write-WARN (T 'invalidOption'); Start-Sleep -Seconds 1 }
        }
    } while ($true)
}

# ============================================================
# CERTIFICATES
# ============================================================
function Get-Certificates {
    param($Device)
    $paths = @(
        '/config/shared/certificate',
        "/config/devices/entry/vsys/entry[@name='vsys1']/certificate"
    )
    $all = @()
    foreach ($p in $paths) {
        $resp = Invoke-PanApi -FWHost $Device.Host -ApiKey $Device.ApiKey -Params @{ type = 'config'; action = 'get'; xpath = $p } -Silent
        if ($resp -and $resp.response.status -eq 'success') {
            $entries = $resp.response.result.certificate.entry
            if ($entries) { $all += @($entries) }
        }
    }
    return , $all
}

function Get-CertExpiry {
    param($Cert)
    $raw = Get-XmlText $Cert.'expiry-epoch'
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    try { return [System.DateTimeOffset]::FromUnixTimeSeconds([long]$raw).LocalDateTime } catch { return $null }
}

function Show-CertificateDashboard {
    param($Device)
    Write-SectionHeader ((T 'certDashboard') -f $Device.Name)
    $certs = Get-Certificates -Device $Device
    if ($certs.Count -eq 0) { Write-WARN (T 'noCertificates'); return }
    $now = Get-Date
    $rows = @()
    foreach ($c in $certs) {
        $exp = Get-CertExpiry $c
        $days = if ($exp) { [int]($exp - $now).TotalDays } else { $null }
        $status = if ($null -eq $days) { T 'certUnknown' }
                  elseif ($days -lt 0) { T 'certExpired' }
                  elseif ($days -le 30) { (T 'certSoon') -f $days }
                  else { (T 'certValid') -f $days }
        $rows += [PSCustomObject]@{
            (T 'dName')    = (Get-XmlText $c.name)
            (T 'dIsCA')    = (Get-XmlText $c.ca)
            (T 'dExpires') = if ($exp) { $exp.ToString('yyyy-MM-dd') } else { 'N/A' }
            Status         = $status
        }
    }
    $pref = @((T 'dName'), (T 'dIsCA'), (T 'dExpires'), 'Status')
    Out-Table -Objects $rows -Preferred $pref
}

function Find-Certificate {
    param($Device, [string]$Name)
    $certs = Get-Certificates -Device $Device
    foreach ($c in $certs) { if ((Get-XmlText $c.name) -eq $Name) { return $c } }
    return $null
}

function Show-CertificateDetail {
    param($Device, [string]$Name)
    Write-SectionHeader ((T 'certDetailTitle') -f $Name)
    $c = Find-Certificate -Device $Device -Name $Name
    if (-not $c) { Write-WARN (T 'certNotFound'); return }
    $exp = Get-CertExpiry $c
    $rows = [ordered]@{
        (T 'dName')      = (Get-XmlText $c.name)
        (T 'dIsCA')      = (Get-XmlText $c.ca)
        (T 'dSubject')   = (Get-XmlText $c.subject)
        (T 'dIssuer')    = (Get-XmlText $c.'issuer-dn')
        (T 'dAlgo')      = (Get-XmlText $c.algorithm)
        (T 'dKeySize')   = (Get-XmlText $c.'key-size')
        (T 'dDigest')    = (Get-XmlText $c.'digest-alg')
        (T 'dValidFrom') = (Get-XmlText $c.'not-valid-before')
        (T 'dExpires')   = if ($exp) { $exp.ToString('yyyy-MM-dd HH:mm') } else { 'N/A' }
        (T 'dSerial')    = (Get-XmlText $c.serial)
        (T 'dThumbprint') = (Get-XmlText $c.thumbprint)
    }
    Write-Host ''
    foreach ($k in $rows.Keys) {
        Write-Host ('  {0,-14}' -f $k) -NoNewline -ForegroundColor $Global:Theme.Header
        Write-Host $rows[$k] -ForegroundColor $Global:Theme.Info
    }
    Write-Host ''
}

function New-CertificateCommand {
    param([string]$CertName, [string]$CN, [string]$Bits, [string]$Digest, [string]$CertType, [string]$SignedBy, [string]$Days)
    $base = "<algorithm><RSA><rsa-nbits>$Bits</rsa-nbits></RSA></algorithm><certificate-name>$CertName</certificate-name><name>$CN</name><digest>$Digest</digest>"
    $type = if ($CertType -eq 'ca') { '<ca>yes</ca>' } else { "<signed-by>$SignedBy</signed-by>" }
    $d = if ($Days -and $Days -ne '0') { "<days>$Days</days>" } else { '' }
    return "<request><certificate><generate>$base$type$d</generate></certificate></request>"
}

function Commit-Changes {
    param($Device)
    if ($Global:Interactive) {
        if (-not (Prompt-Confirm ("Commit changes to $($Device.Name)?"))) { return }
    }
    $resp = Invoke-PanApi -FWHost $Device.Host -ApiKey $Device.ApiKey -Params @{ type = 'commit'; cmd = '<commit></commit>' } -TimeoutSec 60
    if ($resp -and $resp.response.status -eq 'success') {
        Write-OK "Commit job: $($resp.response.result.job)"
    } else {
        Write-WARN "Commit not queued or error: $(Format-PanError $resp)"
    }
}

function Import-PanCertificateFile {
    param([string]$FWHost, [string]$ApiKey, [string]$CertName, [string]$FilePath, [string]$Format = 'pem', [string]$Passphrase = '')
    $passParam = if ($Passphrase) { "&passphrase=$([Uri]::EscapeDataString($Passphrase))" } else { '' }
    $uri = "https://$FWHost/api/?type=import&category=keypair&certificate-name=$([Uri]::EscapeDataString($CertName))&format=$Format$passParam"
    try {
        Add-Type -AssemblyName System.Net.Http
        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.ServerCertificateCustomValidationCallback = [System.Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
        $client = New-Object System.Net.Http.HttpClient($handler)
        $client.DefaultRequestHeaders.Add('X-PAN-KEY', $ApiKey)
        $content = New-Object System.Net.Http.MultipartFormDataContent
        $fileStream = [System.IO.File]::OpenRead($FilePath)
        $streamContent = New-Object System.Net.Http.StreamContent($fileStream)
        $content.Add($streamContent, 'file', (Split-Path $FilePath -Leaf))
        $result = $client.PostAsync($uri, $content).Result
        $respText = $result.Content.ReadAsStringAsync().Result
        $fileStream.Close()
        $client.Dispose()
        return [xml]$respText
    } catch {
        Write-ERR ((T 'certImportFailed') -f $_.Exception.Message)
        return $null
    }
}

function Menu-Certificates {
    param($Device)
    do {
        Write-Banner
        $groups = @(
            @{ Items = @(
                    @{ Key = '1'; Label = (T 'certMenuDashboard') }, @{ Key = '2'; Label = (T 'certMenuValidate') }
                    @{ Key = '3'; Label = (T 'certMenuDetail') }, @{ Key = '4'; Label = (T 'certMenuGenerate') }
                    @{ Key = '5'; Label = (T 'certMenuImport') }, @{ Key = '6'; Label = (T 'certMenuExport') }
                    @{ Key = '7'; Label = (T 'certMenuDelete') }
                )
            }
        )
        Write-Menu -Title "$(T 'certTitle') - $($Device.Name) ($($Device.Host))" -Groups $groups -BackLabel (T 'back')
        switch (Prompt-Input (T 'selectOption')) {
            '1' { Show-CertificateDashboard -Device $Device; Pause-Enter }
            '2' {
                $certs = Get-Certificates -Device $Device
                if ($certs.Count -eq 0) { Write-WARN (T 'noCertificates') } else {
                    $now = Get-Date
                    foreach ($c in $certs) {
                        $exp = Get-CertExpiry $c
                        $days = if ($exp) { [int]($exp - $now).TotalDays } else { $null }
                        $tag = if ($null -eq $days) { T 'certUnknown' } elseif ($days -lt 0) { T 'certExpired' } elseif ($days -le 30) { (T 'certSoon') -f $days } else { (T 'certValid') -f $days }
                        Write-Host ('  {0,-40} {1}' -f (Get-XmlText $c.name), $tag)
                    }
                }
                Pause-Enter
            }
            '3' { $n = Prompt-Input (T 'certNamePrompt'); Show-CertificateDetail -Device $Device -Name $n; Pause-Enter }
            '4' {
                Write-Host "  $(T 'certTypeOpts')"
                $t = Prompt-Input (T 'certTypePrompt')
                if ($t -notin @('1', '2')) { break }
                $certName = Prompt-Input (T 'certNewNamePrompt')
                $cn = Prompt-Input (T 'certCnPrompt')
                $bits = Prompt-Input (T 'certBitsPrompt'); if (-not $bits) { $bits = '2048' }
                $digest = Prompt-Input (T 'certDigestPrompt'); if (-not $digest) { $digest = 'sha256' }
                $signedBy = ''
                if ($t -eq '2') {
                    $caCerts = @(Get-Certificates -Device $Device | Where-Object { (Get-XmlText $_.ca) -eq 'yes' })
                    if ($caCerts.Count -eq 0) { Write-ERR (T 'certNoCa'); Pause-Enter; break }
                    for ($i = 0; $i -lt $caCerts.Count; $i++) { Write-Host ('  [{0}] {1}' -f ($i + 1), (Get-XmlText $caCerts[$i].name)) }
                    $sel = [int](Prompt-Input (T 'certSelectCa'))
                    if ($sel -lt 1 -or $sel -gt $caCerts.Count) { Write-ERR (T 'invalidSelection'); Pause-Enter; break }
                    $signedBy = Get-XmlText $caCerts[$sel - 1].name
                }
                $days = Prompt-Input (T 'certDaysPrompt'); if (-not $days) { $days = '365' }
                $type = if ($t -eq '1') { 'ca' } else { 'signed' }
                $cmd = New-CertificateCommand -CertName $certName -CN $cn -Bits $bits -Digest $digest -CertType $type -SignedBy $signedBy -Days $days
                $resp = Invoke-PanApi -FWHost $Device.Host -ApiKey $Device.ApiKey -Params @{ type = 'op'; cmd = $cmd } -TimeoutSec 60
                if ($resp -and $resp.response.status -eq 'success') { Write-OK ((T 'certGenerated') -f $certName); Commit-Changes -Device $Device }
                else { Write-ERR ((T 'certGenFailed') -f (Format-PanError $resp)) }
                Pause-Enter
            }
            '5' {
                $certName = Prompt-Input (T 'certNameFwPrompt')
                $filePath = Prompt-Input (T 'certFilePrompt')
                $format = Prompt-Input (T 'certFormatPrompt'); if (-not $format) { $format = 'pem' }
                $pass = Prompt-Input (T 'certPassPrompt') -IsPassword
                if (-not (Test-Path -LiteralPath $filePath)) { Write-ERR ((T 'certFileNotFound') -f $filePath); Pause-Enter; break }
                $resp = Import-PanCertificateFile -FWHost $Device.Host -ApiKey $Device.ApiKey -CertName $certName -FilePath $filePath -Format $format -Passphrase $pass
                if ($resp -and $resp.response.status -eq 'success') { Write-OK (T 'certImported'); Commit-Changes -Device $Device }
                else { Write-ERR ((T 'certImportFailed') -f (Format-PanError $resp)) }
                Pause-Enter
            }
            '6' {
                $certName = Prompt-Input (T 'certNamePrompt')
                if (-not $certName) { break }
                $outPath = Prompt-Input (T 'certOutPrompt')
                $format = Prompt-Input (T 'certFormatPrompt'); if (-not $format) { $format = 'pem' }
                try {
                    Invoke-WebRequest -Uri "https://$($Device.Host)/api/" -Method Post `
                        -Headers @{ 'X-PAN-KEY' = $Device.ApiKey } `
                        -Body @{ type = 'export'; category = 'certificate'; 'certificate-name' = $certName; format = $format; 'include-key' = 'yes' } `
                        -OutFile $outPath -SkipCertificateCheck -TimeoutSec 60 -ErrorAction Stop
                    Write-OK ((T 'certExported') -f $outPath)
                } catch { Write-ERR ((T 'certExportFailed') -f $_.Exception.Message) }
                Pause-Enter
            }
            '7' {
                $certName = Prompt-Input (T 'certDeleteNamePrompt')
                if (-not $certName) { break }
                if (-not (Prompt-Confirm ((T 'certDeleteConfirm') -f $certName))) { break }
                $xpaths = @(
                    "/config/shared/certificate/entry[@name='$certName']",
                    "/config/devices/entry/vsys/entry[@name='vsys1']/certificate/entry[@name='$certName']"
                )
                $ok = $false
                foreach ($xp in $xpaths) {
                    $resp = Invoke-PanApi -FWHost $Device.Host -ApiKey $Device.ApiKey -Params @{ type = 'config'; action = 'delete'; xpath = $xp } -Silent
                    if ($resp -and $resp.response.status -eq 'success') { $ok = $true; break }
                }
                if ($ok) { Write-OK ((T 'certDeleted') -f $certName); Commit-Changes -Device $Device } else { Write-ERR (T 'certDeleteFailed') }
                Pause-Enter
            }
            '0' { return }
            default { Write-WARN (T 'invalidOption'); Start-Sleep -Seconds 1 }
        }
    } while ($true)
}

# ============================================================
# DEVICE MANAGEMENT MENUS
# ============================================================
function Add-Device {
    Write-SectionHeader (T 'devAdd')
    $name = Prompt-Input (T 'addName')
    $host_ = Prompt-Input (T 'addHost')
    if (-not $host_) { Write-ERR (T 'addHostRequired'); Pause-Enter; return }
    $version = Prompt-Input (T 'addVersion')
    Write-Host "  [1] $(T 'addAuth1')   [2] $(T 'addAuth2')"
    $auth = Prompt-Input (T 'addAuth')
    $apiKey = $null
    if ($auth -eq '2') {
        $u = Prompt-Input (T 'addUser')
        $p = Prompt-Input (T 'addPass') -IsPassword
        Write-INFO ((T 'addKeyGen') -f $host_)
        $apiKey = Get-ApiKey -FWHost $host_ -User $u -Password $p
        if (-not $apiKey) { Write-ERR (T 'addKeyFail'); Pause-Enter; return }
        Write-OK (T 'addKeyGenOk')
    } else {
        $apiKey = (Prompt-Input 'API Key').Trim()
        if (-not $apiKey) { Write-ERR (T 'addKeyEmpty'); Pause-Enter; return }
    }
    $sys = Test-DeviceConnection ([PSCustomObject]@{ Host = $host_; ApiKey = $apiKey })
    if ($sys) {
        Write-OK ((T 'connOk') -f $sys.hostname, $sys.'sw-version')
        if (-not $version) { $version = $sys.'sw-version' }
    } else {
        Write-WARN (T 'connFailWarn')
        if (-not (Prompt-Confirm (T 'saveAnyway'))) { Pause-Enter; return }
    }
    $Global:Devices += [PSCustomObject]@{
        Name         = if ($name) { $name } else { $host_ }
        Host         = $host_
        PanOSVersion = $version
        ApiKey       = $apiKey
        AddedDate    = (Get-Date).ToString('yyyy-MM-dd HH:mm')
    }
    Save-Config
    Write-OK (T 'deviceSaved')
    Pause-Enter
}

function List-Devices {
    Write-SectionHeader (T 'devicesTitle')
    if ($Global:Devices.Count -eq 0) { Write-WARN (T 'noDevices'); return }
    for ($i = 0; $i -lt $Global:Devices.Count; $i++) {
        $d = $Global:Devices[$i]
        Write-Host ('  [{0}] {1}  ({2})  PAN-OS: {3}  {4}' -f ($i + 1), $d.Name, $d.Host, $d.PanOSVersion, $d.AddedDate)
    }
}

function Remove-Device {
    $idx = Get-DeviceIndex
    if ($idx -lt 0) { return }
    $d = $Global:Devices[$idx]
    if (-not (Prompt-Confirm ((T 'removeConfirm') -f $d.Name, $d.Host))) { return }
    $Global:Devices = @($Global:Devices | Where-Object { $_ -ne $d })
    Save-Config
    Write-OK (T 'deviceRemoved')
}

function Refresh-ApiKey {
    $idx = Get-DeviceIndex
    if ($idx -lt 0) { return }
    $d = $Global:Devices[$idx]
    $u = Prompt-Input (T 'addUser')
    $p = Prompt-Input (T 'addPass') -IsPassword
    $key = Get-ApiKey -FWHost $d.Host -User $u -Password $p
    if ($key) { $Global:Devices[$idx].ApiKey = $key; Save-Config; Write-OK ((T 'keyRenewed') -f $d.Name) }
}

function Menu-Devices {
    do {
        Write-Banner
        $groups = @(
            @{ Items = @(
                    @{ Key = '1'; Label = (T 'devList') }, @{ Key = '2'; Label = (T 'devAdd') }
                    @{ Key = '3'; Label = (T 'devRemove') }, @{ Key = '4'; Label = (T 'devRenew') }
                    @{ Key = '5'; Label = (T 'devTest') }, @{ Key = '6'; Label = (T 'devPerms') }
                )
            }
        )
        Write-Menu -Title (T 'devTitle') -Groups $groups -BackLabel (T 'back')
        switch (Prompt-Input (T 'selectOption')) {
            '1' { List-Devices; Pause-Enter }
            '2' { Add-Device }
            '3' { Remove-Device; Pause-Enter }
            '4' { Refresh-ApiKey; Pause-Enter }
            '5' {
                $d = Select-Device
                if ($d) {
                    $sys = Test-DeviceConnection $d
                    if ($sys) { Write-OK ((T 'connOkShort') -f $sys.hostname, $sys.'sw-version') } else { Write-ERR (T 'connFailed') }
                }
                Pause-Enter
            }
            '6' {
                $d = Select-Device
                if ($d) { Test-ApiPermissions -Device $d }
                Pause-Enter
            }
            '0' { return }
            default { Write-WARN (T 'invalidOption'); Start-Sleep -Seconds 1 }
        }
    } while ($true)
}

# ============================================================
# LANGUAGE MENU
# ============================================================
function Menu-Language {
    Write-Banner
    $groups = @(
        @{ Items = @(
                @{ Key = '1'; Label = (T 'langEnglish') }
                @{ Key = '2'; Label = (T 'langSpanish') }
            )
        }
    )
    Write-Menu -Title (T 'langTitle') -Groups $groups -BackLabel (T 'back')
    $sel = Prompt-Input (T 'langSelect')
    switch ($sel) {
        '1' { $Global:UiLang = 'en' }
        '2' { $Global:UiLang = 'es' }
        '0' { return }
        default { Write-WARN (T 'invalidOption'); Start-Sleep -Seconds 1; return }
    }
    Save-Settings
    Write-OK (T 'langSet')
    Start-Sleep -Seconds 1
}

# ============================================================
# INTERACTIVE SEARCH MENUS
# ============================================================
function Get-LogFilterFields {
    param([string]$LogType)
    switch ($LogType) {
        'traffic'       { return @('src', 'dst', 'dport', 'app', 'window') }
        'threat'        { return @('src', 'dst', 'severity', 'window') }
        'url'           { return @('src', 'dst', 'domain', 'window') }
        'wildfire'      { return @('src', 'dst', 'window') }
        'data'          { return @('src', 'dst', 'app', 'window') }
        'decryption'    { return @('src', 'dst', 'window') }
        'config'        { return @('admin', 'cmd', 'path', 'window') }
        'system'        { return @('src', 'window') }
        'auth'          { return @('src', 'user', 'window') }
        'userid'        { return @('src', 'user', 'window') }
        'globalprotect' { return @('src', 'user', 'window') }
        'hipmatch'      { return @('src', 'user', 'window') }
        'corr'          { return @('src', 'dst', 'window') }
        'gtp'           { return @('src', 'dst', 'window') }
        'iptag'         { return @('src', 'window') }
        'external'      { return @('src', 'dst', 'window') }
        default         { return @('src', 'dst', 'window') }
    }
}

function Read-LogQueryInteractive {
    param([string]$LogType)
    $src = ''; $dst = ''; $dport = ''; $app = ''; $domain = ''; $sev = ''; $user = ''; $since = ''
    $extra = @()
    foreach ($f in (Get-LogFilterFields -LogType $LogType)) {
        switch ($f) {
            'src'      { $src = Prompt-Input (T 'srcPrompt') }
            'dst'      { $dst = Prompt-Input (T 'dstPrompt') }
            'dport'    { $dport = Prompt-Input (T 'dportPrompt') }
            'app'      { $app = Prompt-Input (T 'appPrompt') }
            'domain'   { $domain = Prompt-Input (T 'domainPrompt') }
            'severity' { $sev = Prompt-Input (T 'severityPrompt') }
            'user'     { $user = Prompt-Input (T 'userPrompt') }
            'admin'    { $a = Prompt-Input (T 'cfgAdminPrompt'); if ($a) { $extra += "(admin eq '$a')" } }
            'cmd'      { $c = Prompt-Input (T 'cfgCmdPrompt'); if ($c) { $extra += "(cmd eq '$c')" } }
            'path'     { $p = Prompt-Input (T 'cfgPathPrompt'); if ($p) { $extra += "(path contains $p)" } }
            'window'   {
                $last = Prompt-Input (T 'windowPrompt')
                if (-not $last) { $last = '24h' }
                $since = Resolve-Since $last
            }
        }
    }
    $extraStr = if ($extra.Count -gt 0) { $extra -join ' and ' } else { '' }
    return (New-PanLogQuery -Since $since -Src $src -Dst $dst -Dport $dport -App $app -Domain $domain -Url $domain -Severity $sev -User $user -Extra $extraStr)
}

function Menu-LogSearch {
    param($Device)
    do {
        Write-Banner
        $groups = @(
            @{ Label = (T 'grpLogCore'); Items = @(
                    @{ Key = '1'; Label = 'traffic' }, @{ Key = '2'; Label = 'threat' }, @{ Key = '3'; Label = 'url' }
                    @{ Key = '4'; Label = 'wildfire' }, @{ Key = '5'; Label = 'data' }, @{ Key = '6'; Label = 'decryption' }
                )
            }
            @{ Label = (T 'grpLogSystem'); Items = @(
                    @{ Key = '7'; Label = 'system' }, @{ Key = '8'; Label = 'auth' }, @{ Key = '9'; Label = 'userid' }
                    @{ Key = '10'; Label = 'globalprotect' }, @{ Key = '11'; Label = 'iptag' }, @{ Key = '12'; Label = 'corr' }
                    @{ Key = '13'; Label = 'gtp' }, @{ Key = '14'; Label = 'external' }, @{ Key = '15'; Label = 'hipmatch' }
                    @{ Key = '16'; Label = 'config' }
                )
            }
            @{ Label = (T 'grpLogAdvanced'); Items = @(@{ Key = '17'; Label = (T 'logAdvanced') }) }
        )
        Write-Menu -Title (T 'logSearchTitle') -Groups $groups -BackLabel (T 'back')
        $t = Prompt-Input (T 'logTypePrompt')
        if ($t -eq '0') { return }
        $map = @{
            '1' = 'traffic'; '2' = 'threat'; '3' = 'url'; '4' = 'wildfire'; '5' = 'data'; '6' = 'decryption'
            '7' = 'system'; '8' = 'auth'; '9' = 'userid'; '10' = 'globalprotect'; '11' = 'iptag'; '12' = 'corr'
            '13' = 'gtp'; '14' = 'external'; '15' = 'hipmatch'; '16' = 'config'
        }
        if ($t -eq '17') {
            $logType = Prompt-Input (T 'logRawType')
            $raw = Prompt-Input (T 'logRawQuery')
            $lim = Prompt-Input ((T 'logLimitPrompt') -f $Limit); if (-not $lim) { $lim = $Limit }
            $dir = Prompt-Input (T 'logDirPrompt'); if ($dir -notin @('forward', 'backward')) { $dir = 'backward' }
            $objs = Invoke-LogSearch -Device $Device -LogType $logType -Query $raw -Limit ([int]$lim) -Dir $dir
            Invoke-ExportPrompt -Objects $objs -BaseName "pan-$logType"
            Pause-Enter
            continue
        }
        if (-not $map.ContainsKey($t)) { Write-WARN (T 'invalidOption'); Start-Sleep -Seconds 1; continue }
        $logType = $map[$t]
        $query = Read-LogQueryInteractive -LogType $logType
        $lim = Prompt-Input ((T 'logLimitPrompt') -f $Limit); if (-not $lim) { $lim = $Limit }
        $dir = Prompt-Input (T 'logDirPrompt'); if ($dir -notin @('forward', 'backward')) { $dir = 'backward' }
        $agg = Prompt-Confirm (T 'logAggPrompt')
        $objs = Invoke-LogSearch -Device $Device -LogType $logType -Query $query -Limit ([int]$lim) -Dir $dir -Aggregate:$agg
        Invoke-ExportPrompt -Objects $objs -BaseName "pan-$logType"
        Pause-Enter
    } while ($true)
}

function Menu-Dns {
    param($Device)
    do {
        Write-Banner
        $groups = @(
            @{ Items = @(
                    @{ Key = '1'; Label = (T 'dnsMenuCheck') }
                    @{ Key = '2'; Label = (T 'dnsMenuSubtypes') }
                    @{ Key = '3'; Label = (T 'dnsMenuConfig') }
                    @{ Key = '4'; Label = (T 'dnsMenuO2D'); Color = $Global:Theme.Highlight }
                )
            }
        )
        Write-Menu -Title (T 'dnsTitle') -Groups $groups -BackLabel (T 'back')
        switch (Prompt-Input (T 'selectOption')) {
            '1' {
                $domain = Prompt-Input (T 'dnsDomainPrompt')
                $last = Prompt-Input (T 'dnsWindowPrompt'); if (-not $last) { $last = '7d' }
                $objs = Test-DnsSecurity -Device $Device -Domain $domain -Last $last
                Invoke-ExportPrompt -Objects $objs -BaseName 'pan-dns-security'
                Pause-Enter
            }
            '2' {
                $last = Prompt-Input (T 'dnsWindowPrompt'); if (-not $last) { $last = '7d' }
                $since = Resolve-Since $last
                $rows = Get-DnsSubtypeList -Device $Device -Since $since
                if ($rows.Count -eq 0) { Write-WARN (T 'noData') } else { Out-ColorTable -Objects $rows -Columns @('Subtype', 'Count') }
                Pause-Enter
            }
            '3' { Show-DnsConfig -Device $Device; Pause-Enter }
            '4' {
                $src = Prompt-Input (T 'o2dSrcPrompt')
                $dst = Prompt-Input (T 'o2dDstPrompt')
                $port = Prompt-Input (T 'dportPrompt')
                $app = Prompt-Input (T 'appPrompt')
                $proto = Prompt-Input (T 'policyProtoPrompt')
                $last = Prompt-Input (T 'windowPrompt'); if (-not $last) { $last = '24h' }
                $objs = Test-FlowSecurity -Device $Device -Src $src -Dst $dst -Port $port -App $app -Protocol $proto -Last $last
                Invoke-ExportPrompt -Objects $objs -BaseName 'pan-flow-test'
                Pause-Enter
            }
            '0' { return }
            default { Write-WARN (T 'invalidOption'); Start-Sleep -Seconds 1 }
        }
    } while ($true)
}

function Menu-Pcap {
    param($Device)
    do {
        Write-Banner
        $groups = @(
            @{ Label = (T 'grpList'); Items = @(
                    @{ Key = '1'; Label = (T 'pcapListApp') }
                    @{ Key = '2'; Label = (T 'pcapListAppDate') }
                )
            }
            @{ Label = (T 'grpDownload'); Items = @(
                    @{ Key = '3'; Label = (T 'pcapDlApp') }
                    @{ Key = '4'; Label = (T 'pcapDlFilters') }
                    @{ Key = '5'; Label = (T 'pcapDlThreat') }
                    @{ Key = '6'; Label = (T 'pcapDlDlp') }
                )
            }
            @{ Label = (T 'grpLive'); Items = @(
                    @{ Key = '7'; Label = (T 'pcapLive'); Color = $Global:Theme.Warning }
                )
            }
        )
        Write-Menu -Title "$(T 'pcapTitle') - $($Device.Name)" -Groups $groups -BackLabel (T 'back')
        switch (Prompt-Input (T 'selectOption')) {
            '1' { Get-PcapListing -Device $Device -Category 'application-pcap'; Pause-Enter }
            '2' {
                $from = Prompt-Input (T 'pcapFromDatePrompt')
                Get-PcapListing -Device $Device -Category 'application-pcap' -From $from; Pause-Enter
            }
            '3' {
                $from = Prompt-Input (T 'pcapFromPrompt')
                $out = Prompt-Input (T 'pcapOutPrompt')
                Export-PcapFile -Device $Device -Category 'application-pcap' -From $from -OutFile $out; Pause-Enter
            }
            '4' {
                Get-PcapListing -Device $Device -Category 'filters-pcap'
                $from = Prompt-Input (T 'pcapFromPrompt')
                $out = Prompt-Input (T 'pcapOutPrompt')
                Export-PcapFile -Device $Device -Category 'filters-pcap' -From $from -OutFile $out; Pause-Enter
            }
            '5' {
                $id = Prompt-Input (T 'pcapPcapIdPrompt')
                $sid = Prompt-Input (T 'pcapSessionIdPrompt')
                $st = Prompt-Input (T 'pcapSearchTimePrompt')
                $dn = Prompt-Input (T 'pcapDevNamePrompt')
                $out = Prompt-Input (T 'pcapOutPrompt')
                Export-ThreatPcap -Device $Device -PcapId $id -SessionId $sid -SearchTime $st -DeviceName $dn -OutFile $out; Pause-Enter
            }
            '6' {
                $pw = Prompt-Input (T 'pcapDlpPassPrompt') -IsPassword
                Get-PcapListing -Device $Device -Category 'dlp-pcap' -DlpPassword $pw
                $from = Prompt-Input (T 'pcapFromPrompt')
                $out = Prompt-Input (T 'pcapOutPrompt')
                Export-PcapFile -Device $Device -Category 'dlp-pcap' -From $from -OutFile $out -DlpPassword $pw; Pause-Enter
            }
            '7' {
                $src = Prompt-Input (T 'liveSrcPrompt')
                $dst = Prompt-Input (T 'liveDstPrompt')
                $port = Prompt-Input (T 'livePortPrompt')
                $sec = Prompt-Input (T 'liveSecPrompt'); if (-not $sec) { $sec = '15' }
                Invoke-LiveCapture -Device $Device -Src $src -Dst $dst -Port $port -Seconds ([int]$sec); Pause-Enter
            }
            '0' { return }
            default { Write-WARN (T 'invalidOption'); Start-Sleep -Seconds 1 }
        }
    } while ($true)
}

function Menu-Reports {
    param($Device)
    $groups = @(
        @{ Items = @(
                @{ Key = '1'; Label = 'top-app-summary' }
                @{ Key = '2'; Label = 'top-blocked-url-summary' }
                @{ Key = '3'; Label = 'top-spyware-threats-summary' }
                @{ Key = '4'; Label = 'top-attackers' }
                @{ Key = '5'; Label = 'top-victims' }
                @{ Key = '6'; Label = (T 'reportNamePrompt') }
                @{ Key = '7'; Label = (T 'reportList') }
            )
        }
    )
    Write-Menu -Title (T 'reportTitle') -Groups $groups -BackLabel (T 'back')
    $sel = Prompt-Input (T 'selectOption')
    if ($sel -eq '0') { return }
    $map = @{
        '1' = 'top-app-summary'; '2' = 'top-blocked-url-summary'; '3' = 'top-spyware-threats-summary'
        '4' = 'top-attackers'; '5' = 'top-victims'
    }
    if ($sel -eq '7') { Show-Report -Device $Device -Type 'dynamic' -Name $null -Period $null -TopN 0; Pause-Enter; return }
    $name = if ($sel -eq '6') { Prompt-Input (T 'reportNamePrompt') } else { $map[$sel] }
    if (-not $name) { Write-WARN (T 'invalidOption'); return }
    $period = Prompt-Input (T 'reportPeriodPrompt')
    if (-not $period) { $period = 'last-24-hrs' }
    $topn = Prompt-Input (T 'reportTopnPrompt'); if (-not $topn) { $topn = '10' }
    $xml = Show-Report -Device $Device -Type 'dynamic' -Name $name -Period $period -TopN ([int]$topn)
    if ($xml -and (Prompt-Confirm (T 'askExport'))) {
        Export-XmlContent -Content $xml -BaseName "pan-report-$name"
    }
    Pause-Enter
}

function Menu-System {
    param($Device)
    do {
        Write-Banner
        $groups = @(
            @{ Label = (T 'grpInfo'); Items = @(
                    @{ Key = '1'; Label = (T 'sysInfoItem') }, @{ Key = '2'; Label = (T 'sysContentItem') }
                    @{ Key = '3'; Label = (T 'sysHaItem') }, @{ Key = '4'; Label = (T 'sysLicItem') }
                    @{ Key = '5'; Label = (T 'sysIfItem') }, @{ Key = '6'; Label = (T 'sysRouteItem') }
                    @{ Key = '7'; Label = (T 'sysArpItem') }, @{ Key = '8'; Label = (T 'sysSessionItem') }
                    @{ Key = '9'; Label = (T 'sysJobsItem') }, @{ Key = '10'; Label = (T 'sysJobDetailItem') }
                )
            }
            @{ Label = (T 'grpAdvanced'); Items = @(
                    @{ Key = '11'; Label = (T 'sysResourcesItem') }, @{ Key = '12'; Label = (T 'sysSessionInfoItem') }
                    @{ Key = '13'; Label = (T 'sysIkeItem') }, @{ Key = '14'; Label = (T 'sysIpsecItem') }
                    @{ Key = '15'; Label = (T 'sysSwItem') }, @{ Key = '16'; Label = (T 'sysSavedItem') }
                    @{ Key = '17'; Label = (T 'sysNtpItem') }, @{ Key = '18'; Label = (T 'sysUseridItem') }
                    @{ Key = '19'; Label = (T 'cpuTitle'); Color = $Global:Theme.Highlight }
                    @{ Key = '20'; Label = (T 'dropsTitle'); Color = $Global:Theme.Highlight }
                )
            }
        )
        Write-Menu -Title "$(T 'sysTitle') - $($Device.Name)" -Groups $groups -BackLabel (T 'back')
        switch (Prompt-Input (T 'selectOption')) {
            '1' { Show-SystemInfo -Device $Device; Pause-Enter }
            '2' { Show-ContentVersions -Device $Device; Pause-Enter }
            '3' { Show-HaStatus -Device $Device; Pause-Enter }
            '4' { Show-Licenses -Device $Device; Pause-Enter }
            '5' { Show-Interfaces -Device $Device; Pause-Enter }
            '6' { Show-Routes -Device $Device; Pause-Enter }
            '7' { Show-Arp -Device $Device; Pause-Enter }
            '8' {
                $src = Prompt-Input (T 'sessionSrcPrompt')
                $dst = Prompt-Input (T 'sessionDstPrompt')
                $app = Prompt-Input (T 'sessionAppPrompt')
                Show-Sessions -Device $Device -Src $src -Dst $dst -App $app; Pause-Enter
            }
            '9' { Show-Jobs -Device $Device; Pause-Enter }
            '10' { $jid = Prompt-Input (T 'histJobIdPrompt'); Show-JobDetail -Device $Device -JobId $jid; Pause-Enter }
            '11' { Show-SimpleOp -Device $Device -Cmd '<show><system><resources></resources></system></show>' -Title (T 'sysResourcesItem'); Pause-Enter }
            '12' { Show-SimpleOp -Device $Device -Cmd '<show><session><info></info></session></show>' -Title (T 'sysSessionInfoItem'); Pause-Enter }
            '13' { Show-SimpleOp -Device $Device -Cmd '<show><vpn><ike-sa></ike-sa></vpn></show>' -Title (T 'sysIkeItem'); Pause-Enter }
            '14' { Show-SimpleOp -Device $Device -Cmd '<show><vpn><ipsec-sa></ipsec-sa></vpn></show>' -Title (T 'sysIpsecItem'); Pause-Enter }
            '15' { Show-SimpleOp -Device $Device -Cmd '<show><system><software><status></status></software></system></show>' -Title (T 'sysSwItem'); Pause-Enter }
            '16' { Show-ConfigSaved -Device $Device; Pause-Enter }
            '17' { Show-SimpleOp -Device $Device -Cmd '<show><ntp></ntp></show>' -Title (T 'sysNtpItem'); Pause-Enter }
            '18' { Show-SimpleOp -Device $Device -Cmd '<show><user><ip-user-mapping><all></all></ip-user-mapping></user></show>' -Title (T 'sysUseridItem'); Pause-Enter }
            '19' { Show-CpuMonitor -Device $Device -Interval $Interval }
            '20' { Menu-Drops -Device $Device }
            '0' { return }
            default { Write-WARN (T 'invalidOption'); Start-Sleep -Seconds 1 }
        }
    } while ($true)
}

function Menu-Policy {
    param($Device)
    Write-SectionHeader (T 'flowTitle')
    Write-WARN (T 'policyExpWarn')
    $src = Prompt-Input (T 'policySrcPrompt')
    $dst = Prompt-Input (T 'policyDstPrompt')
    if (-not $src -or -not $dst) { Write-WARN (T 'o2dNeedSrcDst'); return }
    $port = Prompt-Input (T 'policyPortPrompt')
    $app = Prompt-Input (T 'policyAppPrompt')
    $proto = Prompt-Input (T 'policyProtoPrompt')
    $last = Prompt-Input (T 'windowPrompt'); if (-not $last) { $last = '24h' }
    $df = Prompt-Input (T 'flowDropsFilter'); if ($df -notin @('all', 'tcp', 'udp', 'frag', 'resource')) { $df = 'all' }
    $objs = Show-FlowInvestigation -Device $Device -Src $src -Dst $dst -Port $port -App $app -Protocol $proto -Last $last -DropsFilter $df
    Invoke-ExportPrompt -Objects $objs -BaseName 'pan-flow-investigation'
    Pause-Enter
}

# ============================================================
# MAIN MENU
# ============================================================
function Show-MainMenu {
    Load-Config
    do {
        Write-Banner
        $line = '-' * ((Get-ConsoleWidth))
        Write-Host $line -ForegroundColor $Global:Theme.Border
        Write-Host ('  ' + ((T 'statusBar') -f $Global:Devices.Count, $Global:UiLang.ToUpper(), (Get-Date -Format 'yyyy-MM-dd HH:mm'))) -ForegroundColor $Global:Theme.Menu
        Write-Host $line -ForegroundColor $Global:Theme.Border
        $groups = @(
            @{ Label = (T 'grpAnalysis'); Items = @(
                    @{ Key = '1'; Label = (T 'menuLogSearch') }, @{ Key = '2'; Label = (T 'menuDns') }
                    @{ Key = '3'; Label = (T 'menuPcap') }, @{ Key = '4'; Label = (T 'menuReports') }
                    @{ Key = 'A'; Label = (T 'menuUserAct'); Color = $Global:Theme.Highlight }
                )
            }
            @{ Label = (T 'grpTools'); Items = @(
                    @{ Key = '5'; Label = (T 'menuSystem') }, @{ Key = '6'; Label = (T 'menuPolicy') }
                    @{ Key = '7'; Label = (T 'menuCert') }, @{ Key = '8'; Label = (T 'menuHistory') }
                )
            }
            @{ Label = (T 'grpSystem'); Items = @(
                    @{ Key = '9'; Label = (T 'menuDevices') }
                    @{ Key = 'L'; Label = (T 'menuLang'); Color = $Global:Theme.Highlight }
                )
            }
            @{ Items = @(
                    @{ Key = '0'; Label = (T 'menuExit'); Color = $Global:Theme.Error }
                )
            }
        )
        Write-Menu -Groups $groups -NoHeader
        $opt = Prompt-Input (T 'selectOption')
        if ($opt -eq '9') { Menu-Devices; continue }
        if ($opt -eq '8') { Menu-History; continue }
        if ($opt -eq 'l') { Menu-Language; continue }
        if ($opt -eq '0') { Write-OK (T 'goodbye'); return }
        $device = Select-Device
        if (-not $device) { Start-Sleep -Seconds 2; continue }
        switch ($opt) {
            '1' { Menu-LogSearch -Device $device }
            '2' { Menu-Dns -Device $device }
            '3' { Menu-Pcap -Device $device }
            '4' { Menu-Reports -Device $device }
            '5' { Menu-System -Device $device }
            '6' { Menu-Policy -Device $device }
            '7' { Menu-Certificates -Device $device }
            'a' { Menu-UserActivity -Device $device }
            default { Write-WARN (T 'invalidOption'); Start-Sleep -Seconds 1 }
        }
    } while ($true)
}

# ============================================================
# NON-INTERACTIVE DISPATCH
# ============================================================
function Invoke-NonInteractive {
    $Global:Interactive = $false
    if ($ListDevices) { Load-Config; List-Devices; return }
    Load-Config
    if ($Global:Devices.Count -eq 0) { Write-ERR (T 'noDevInteractive'); return }
    $device = Resolve-DeviceObject $Device
    if (-not $device) {
        if ($Global:Devices.Count -eq 1) { $device = $Global:Devices[0] }
        else { Write-ERR ((T 'deviceNotFound') -f $Device); return }
    }
    Write-Host ((T 'deviceLabel') -f $device.Name, $device.Host) -ForegroundColor $Global:Theme.Device

    switch ($Action) {
        'test' {
            $sys = Test-DeviceConnection $device
            if ($sys) { Write-OK ((T 'connOkShort') -f $sys.hostname, $sys.'sw-version') } else { Write-ERR (T 'connFailed') }
        }
        { $_ -in @('traffic', 'threat', 'url', 'wildfire', 'data', 'decryption', 'auth', 'userid', 'globalprotect', 'iptag', 'corr', 'gtp', 'external', 'hipmatch', 'log-system') } {
            $since = Resolve-Since $Last
            $lt = if ($Action -eq 'log-system') { 'system' } else { $Action }
            $query = New-PanLogQuery -Since $since -Src $Src -Dst $Dst -Dport $Port -Sport $Sport -App $App -Domain $Domain -Url $Url -Severity $Severity -Rule $Rule -User $User
            Invoke-LogSearch -Device $device -LogType $lt -Query $query -Limit $Limit -DoExport:$Export | Out-Null
        }
        'dns' {
            Test-DnsSecurity -Device $device -Domain $Domain -Last $Last -DoExport:$Export | Out-Null
        }
        'commits' {
            Get-PanCommitHistory -Device $device -Limit $Limit -DoExport:$Export | Out-Null
        }
        'config-changes' {
            Get-PanConfigChanges -Device $device -Last $Last -Admin $Admin -Limit $Limit -DoExport:$Export | Out-Null
        }
        'pending' {
            Show-PendingChanges -Device $device
        }
        'pcap-list' {
            Get-PcapListing -Device $device -Category $PcapCategory -From $PcapFrom -DlpPassword $DlpPassword
        }
        'pcap-download' {
            if ($PcapId) {
                Export-ThreatPcap -Device $device -PcapId $PcapId -SessionId $SessionId -SearchTime $SearchTime -DeviceName $device.Name
            } else {
                Export-PcapFile -Device $device -Category $PcapCategory -From $PcapFrom -DlpPassword $DlpPassword -OutFile $null
            }
        }
        'report' {
            Show-Report -Device $device -Type $ReportType -Name $ReportName -Period $Period -TopN $TopN -DoExport:$Export
        }
        'system'    { Show-SystemInfo -Device $device }
        'content'   { Show-ContentVersions -Device $device }
        'ha'        { Show-HaStatus -Device $device }
        'licenses'  { Show-Licenses -Device $device }
        'interfaces' { Show-Interfaces -Device $device }
        'routes'    { Show-Routes -Device $device }
        'arp'       { Show-Arp -Device $device }
        'sessions'  { Show-Sessions -Device $device -Src $Src -Dst $Dst -App $App }
        'jobs'      { Show-Jobs -Device $device }
        'job-detail' { Show-JobDetail -Device $device -JobId $JobId }
        'resources' { Show-SimpleOp -Device $device -Cmd '<show><system><resources></resources></system></show>' -Title (T 'sysResourcesItem') }
        'session-info' { Show-SimpleOp -Device $device -Cmd '<show><session><info></info></session></show>' -Title (T 'sysSessionInfoItem') }
        'vpn-ike'   { Show-SimpleOp -Device $device -Cmd '<show><vpn><ike-sa></ike-sa></vpn></show>' -Title (T 'sysIkeItem') }
        'vpn-ipsec' { Show-SimpleOp -Device $device -Cmd '<show><vpn><ipsec-sa></ipsec-sa></vpn></show>' -Title (T 'sysIpsecItem') }
        'sw-status' { Show-SimpleOp -Device $device -Cmd '<show><system><software><status></status></software></system></show>' -Title (T 'sysSwItem') }
        'config-saved' { Show-ConfigSaved -Device $device }
        'ntp'       { Show-SimpleOp -Device $device -Cmd '<show><ntp></ntp></show>' -Title (T 'sysNtpItem') }
        'userid-map' { Show-SimpleOp -Device $device -Cmd '<show><user><ip-user-mapping><all></all></ip-user-mapping></user></show>' -Title (T 'sysUseridItem') }
        'perms'     { Test-ApiPermissions -Device $device }
        'cpu'       { Show-CpuMonitor -Device $device -Interval $Interval -Iterations $Iterations }
        'drops'     { Show-PacketDrops -Device $device -Filter $Filter -DoExport:$Export | Out-Null }
        'o2d'       { Test-FlowSecurity -Device $device -Src $Src -Dst $Dst -Port $Port -App $App -Protocol $Protocol -Last $Last -DoExport:$Export | Out-Null }
        'flow'      { Show-FlowInvestigation -Device $device -Src $Src -Dst $Dst -Port $Port -App $App -Protocol $Protocol -Last $Last -DropsFilter $Filter -DoExport:$Export | Out-Null }
        'activity'  { Show-UserActivity -Device $device -Src $Src -Interval $Interval -Last $Last -Iterations $Iterations }
        'dns-config' { Show-DnsConfig -Device $device }
        'dns-subtypes' {
            $since = Resolve-Since $Last
            $rows = Get-DnsSubtypeList -Device $device -Since $since
            if ($rows.Count -eq 0) { Write-WARN (T 'noData') } else { Out-ColorTable -Objects $rows -Columns @('Subtype', 'Count') }
        }
        'config-diff' { Show-RunningCandidateDiff -Device $device -DoExport:$Export | Out-Null }
        'policy' {
            $resp = Test-PolicyMatch -Device $device -Src $Src -Dst $Dst -Port $Port -App $App -Protocol $Protocol -FromZone $FromZone -ToZone $ToZone
            if ($resp) { Show-OpResult -Resp $resp -Title (T 'policyTitle') }
        }
        'cert-list'     { Show-CertificateDashboard -Device $device }
        'cert-validate' {
            $certs = Get-Certificates -Device $device
            $now = Get-Date
            $rows = foreach ($c in $certs) {
                $exp = Get-CertExpiry $c
                $days = if ($exp) { [int]($exp - $now).TotalDays } else { $null }
                [PSCustomObject]@{
                    Name    = (Get-XmlText $c.name)
                    Expires = if ($exp) { $exp.ToString('yyyy-MM-dd') } else { 'N/A' }
                    Days    = $days
                    Status  = if ($null -eq $days) { T 'certUnknown' } elseif ($days -lt 0) { T 'certExpired' } elseif ($days -le 30) { (T 'certSoon') -f $days } else { (T 'certValid') -f $days }
                }
            }
            Out-ColorTable -Objects $rows -Columns @('Name', 'Expires', 'Days', 'Status') -ColorMap @{
                'Status' = { param($v) Get-StatusColor $v }
            }
            if ($Export) { Export-Results -Objects $rows -BaseName 'pan-certificates' -Format $Format -OutDir $Global:OutputDir }
        }
        'devices'   { List-Devices }
        default     { Write-WARN (T 'unknownAction') }
    }
}

# ============================================================
# ENTRY POINT
# ============================================================
Load-Settings
if ($Lang) { $Global:UiLang = $Lang }

if ($Action -or $ListDevices) {
    Invoke-NonInteractive
} else {
    Show-MainMenu
}

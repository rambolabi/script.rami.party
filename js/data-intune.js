'use strict';

/* ============================================================================
   Intune script library: custom compliance, Win32 app detection and
   detection/remediation pairs that check whether software is installed
   or running.

   Conventions the builders follow:
     Custom compliance   discovery script returns one compressed JSON line,
                         the companion rules file is emitted as a block
                         comment ready to save as .json.
     Remediations        detection exits 0 when healthy, 1 to trigger the
                         remediation script.
     Win32 detection     exit 0 plus output on STDOUT means installed.
   ========================================================================== */

(function () {
  const q = v => String(v == null ? '' : v).trim().replace(/'/g, "''");
  const num = (v, d) => (parseInt(v, 10) > 0 ? parseInt(v, 10) : d);
  const settingName = v => String(v).replace(/[^A-Za-z0-9]/g, '');

  const REQ_COMPLIANCE = 'Intune custom compliance: upload the .ps1 as the discovery script and the JSON as the rules file, then reference both from a Windows compliance policy.';
  const REQ_REMEDIATION = 'Intune remediations (Devices, Scripts and remediations): upload detection and remediation as separate .ps1 files. Run in 64-bit PowerShell.';
  const REQ_WIN32 = 'Intune Win32 app: use as a custom detection script. Exit code 0 together with STDOUT output means the app is detected.';

  function uninstallKeys(includeUsers) {
    const lines = [
      '$uninstallKeys = @(',
      "    'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'",
      "    'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'"
    ];
    if (includeUsers) lines.push("    'Registry::HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'");
    lines.push(')');
    return lines;
  }

  /* rules: array of [SettingName, Operator, DataType, Operand, Title] */
  function rulesJson(rules) {
    return JSON.stringify({
      Rules: rules.map(r => ({
        SettingName: r[0],
        Operator: r[1],
        DataType: r[2],
        Operand: r[3],
        MoreInfoUrl: 'https://script.rami.party',
        RemediationStrings: [{ Language: 'en_US', Title: r[4], Description: r[4] }]
      }))
    }, null, 2);
  }

  function compliancePackage(sel, scriptLines, rules, fileName) {
    const parts = [];
    if (sel.output !== 'rules') {
      parts.push('# === Discovery script, upload as ' + fileName + '.ps1 ===');
      parts.push(scriptLines.join('\n'));
    }
    if (sel.output !== 'script') {
      parts.push('');
      parts.push('# === Rules file, save the JSON below as ' + fileName + '.json ===');
      parts.push('<#');
      parts.push(rulesJson(rules));
      parts.push('#>');
    }
    return parts.join('\n').trim();
  }

  const OUTPUT_GROUP = {
    id: 'output', label: 'Output', type: 'single', items: [
      { id: 'both', label: 'Discovery script + rules file', default: true },
      { id: 'script', label: 'Discovery script only' },
      { id: 'rules', label: 'Rules file only' }
    ]
  };

  const SCRIPTS_INTUNE = [];
  const add = e => SCRIPTS_INTUNE.push(Object.assign({ language: 'PowerShell' }, e));

  /* ------------------------------------------------------ custom compliance */

  add({
    id: 'intune-compliance-software-installed',
    title: 'Compliance: application installed',
    purposes: ['Intune', 'Compliance'],
    description: 'Custom compliance check that an application is installed, at or above a minimum version, read from the registry uninstall keys the way Intune sees them.',
    requires: REQ_COMPLIANCE,
    keywords: 'intune custom compliance discovery script json rules software installed displayname displayversion uninstall registry',
    options: [
      { id: 'app', label: 'Application name (wildcards allowed)', type: 'text', placeholder: '7-Zip*' },
      { id: 'minVersion', label: 'Minimum version (optional)', type: 'text', placeholder: '23.0' },
      {
        id: 'checks', label: 'Also check', type: 'multi', items: [
          { id: 'userScope', label: 'Per-user installs (HKEY_USERS)', default: true },
          { id: 'process', label: 'A process is currently running' }
        ]
      },
      { id: 'proc', label: 'Process name, without .exe', type: 'text', placeholder: '7zFM' },
      OUTPUT_GROUP
    ],
    build: sel => {
      const app = q(sel.app) || '7-Zip*';
      const minVersion = q(sel.minVersion);
      const proc = q(sel.proc);
      const wantProcess = sel.checks.has('process') && proc;

      const script = ["$appName = '" + app + "'"]
        .concat(uninstallKeys(sel.checks.has('userScope')))
        .concat([
          '$apps = Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |',
          '    Where-Object { $_.DisplayName -like $appName }',
          '$installed = [bool]$apps',
          '$version = $apps | ForEach-Object {',
          "    try { [version]($_.DisplayVersion -replace '[^\\d\\.].*$') } catch { $null }",
          '} | Sort-Object -Descending | Select-Object -First 1',
          ''
        ]);

      const rules = [
        ['SoftwareInstalled', 'IsEquals', 'Boolean', true, app.replace(/\*/g, '') + ' must be installed']
      ];
      const resultLines = [
        '$result = [ordered]@{',
        '    SoftwareInstalled = $installed',
        "    DetectedVersion   = [string]$version"
      ];
      if (minVersion) {
        script.push("$minimumVersion = [version]'" + minVersion + "'");
        resultLines.push('    VersionCompliant  = [bool]($installed -and $version -and $version -ge $minimumVersion)');
        rules.push(['VersionCompliant', 'IsEquals', 'Boolean', true, app.replace(/\*/g, '') + ' must be version ' + minVersion + ' or later']);
      }
      if (wantProcess) {
        resultLines.push("    ProcessRunning    = [bool](Get-Process -Name '" + proc + "' -ErrorAction SilentlyContinue)");
        rules.push(['ProcessRunning', 'IsEquals', 'Boolean', true, proc + ' must be running']);
      }
      resultLines.push('}');
      script.push(...resultLines);
      script.push('return $result | ConvertTo-Json -Compress');

      return compliancePackage(sel, script, rules, 'SoftwareInstalled');
    }
  });

  add({
    id: 'intune-compliance-process-running',
    title: 'Compliance: processes running',
    purposes: ['Intune', 'Compliance'],
    description: 'Custom compliance check that one or more processes are running right now, for agents the business says must always be active.',
    requires: REQ_COMPLIANCE,
    keywords: 'intune custom compliance process running get-process agent edr av must run discovery json',
    options: [
      { id: 'procs', label: 'Process names, comma separated, without .exe', type: 'text', placeholder: 'MsMpEng, SenseIR' },
      OUTPUT_GROUP
    ],
    build: sel => {
      const names = (q(sel.procs) || 'MsMpEng').split(',').map(s => s.trim()).filter(Boolean);
      const width = Math.max.apply(null, names.map(n => settingName('Running' + n).length)) + 1;
      const script = ['$result = [ordered]@{'];
      const rules = [];
      names.forEach(n => {
        const key = settingName('Running' + n);
        script.push('    ' + key + ' '.repeat(Math.max(1, width - key.length)) + "= [bool](Get-Process -Name '" + n.replace(/'/g, "''") + "' -ErrorAction SilentlyContinue)");
        rules.push([key, 'IsEquals', 'Boolean', true, n + ' must be running']);
      });
      script.push('}');
      script.push('return $result | ConvertTo-Json -Compress');
      return compliancePackage(sel, script, rules, 'ProcessRunning');
    }
  });

  add({
    id: 'intune-compliance-service',
    title: 'Compliance: service present and running',
    purposes: ['Intune', 'Compliance'],
    description: 'Custom compliance check that a Windows service exists, is running and starts automatically.',
    requires: REQ_COMPLIANCE,
    keywords: 'intune custom compliance service running starttype automatic windefend exists discovery json',
    options: [
      { id: 'svc', label: 'Service name', type: 'text', placeholder: 'WinDefend' },
      {
        id: 'checks', label: 'Require', type: 'multi', items: [
          { id: 'running', label: 'Service is running', default: true },
          { id: 'auto', label: 'Startup type is automatic', default: true }
        ]
      },
      OUTPUT_GROUP
    ],
    build: sel => {
      const svc = q(sel.svc) || 'WinDefend';
      const script = [
        "$service = Get-Service -Name '" + svc + "' -ErrorAction SilentlyContinue",
        '$result = [ordered]@{',
        '    ServiceExists  = [bool]$service'
      ];
      const rules = [['ServiceExists', 'IsEquals', 'Boolean', true, svc + ' must be installed']];
      if (sel.checks.has('running')) {
        script.push("    ServiceRunning = [bool]($service -and $service.Status -eq 'Running')");
        rules.push(['ServiceRunning', 'IsEquals', 'Boolean', true, svc + ' must be running']);
      }
      if (sel.checks.has('auto')) {
        script.push("    StartAutomatic = [bool]($service -and $service.StartType -like 'Automatic*')");
        rules.push(['StartAutomatic', 'IsEquals', 'Boolean', true, svc + ' must start automatically']);
      }
      script.push('}');
      script.push('return $result | ConvertTo-Json -Compress');
      return compliancePackage(sel, script, rules, 'Service' + settingName(svc));
    }
  });

  add({
    id: 'intune-compliance-defender',
    title: 'Compliance: Defender healthy',
    purposes: ['Intune', 'Compliance'],
    description: 'Custom compliance check on Microsoft Defender: real-time protection on, tamper protection on and signatures fresh.',
    requires: REQ_COMPLIANCE,
    keywords: 'intune custom compliance defender get-mpcomputerstatus realtimeprotection tamper signature age antivirus health',
    options: [
      {
        id: 'checks', label: 'Require', type: 'multi', items: [
          { id: 'rtp', label: 'Real-time protection enabled', default: true },
          { id: 'av', label: 'Antivirus engine enabled', default: true },
          { id: 'tamper', label: 'Tamper protection enabled', default: true },
          { id: 'age', label: 'Signatures no older than the limit', default: true }
        ]
      },
      { id: 'maxAge', label: 'Maximum signature age (days)', type: 'number', placeholder: '7', value: '7' },
      OUTPUT_GROUP
    ],
    build: sel => {
      const maxAge = num(sel.maxAge, 7);
      const script = ['$status = Get-MpComputerStatus', '$result = [ordered]@{'];
      const rules = [];
      if (sel.checks.has('rtp')) {
        script.push('    RealTimeProtection = [bool]$status.RealTimeProtectionEnabled');
        rules.push(['RealTimeProtection', 'IsEquals', 'Boolean', true, 'Real-time protection must be enabled']);
      }
      if (sel.checks.has('av')) {
        script.push('    AntivirusEnabled   = [bool]$status.AntivirusEnabled');
        rules.push(['AntivirusEnabled', 'IsEquals', 'Boolean', true, 'The antivirus engine must be enabled']);
      }
      if (sel.checks.has('tamper')) {
        script.push('    TamperProtection   = [bool]$status.IsTamperProtected');
        rules.push(['TamperProtection', 'IsEquals', 'Boolean', true, 'Tamper protection must be enabled']);
      }
      if (sel.checks.has('age')) {
        script.push('    SignatureAgeDays   = [int]$status.AntivirusSignatureAge');
        rules.push(['SignatureAgeDays', 'LessThanOrEquals', 'Int64', maxAge, 'Signatures must be at most ' + maxAge + ' days old']);
      }
      script.push('}');
      script.push('return $result | ConvertTo-Json -Compress');
      return compliancePackage(sel, script, rules, 'DefenderHealth');
    }
  });

  /* -------------------------------------------------------- Win32 detection */

  add({
    id: 'intune-win32-detection',
    title: 'Win32 app detection script',
    purposes: ['Intune'],
    description: 'Detection script for a Win32 app package: by registry display name, by file version or by MSI product code.',
    requires: REQ_WIN32,
    keywords: 'intune win32 app detection script custom exit 0 stdout registry displayname file version msi product code intunewin',
    options: [
      {
        id: 'method', label: 'Detection method', type: 'single', items: [
          { id: 'registry', label: 'Registry display name', default: true },
          { id: 'file', label: 'File exists with version' },
          { id: 'msi', label: 'MSI product code' }
        ]
      },
      { id: 'app', label: 'Application name (registry method)', type: 'text', placeholder: '7-Zip*' },
      { id: 'path', label: 'File path (file method)', type: 'text', placeholder: 'C:\\Program Files\\7-Zip\\7z.exe' },
      { id: 'code', label: 'Product code (MSI method)', type: 'text', placeholder: '{23170F69-40C1-2702-2301-000001000000}' },
      { id: 'minVersion', label: 'Minimum version (optional)', type: 'text', placeholder: '23.0' }
    ],
    build: sel => {
      const minVersion = q(sel.minVersion);
      if (sel.method === 'file') {
        const path = q(sel.path) || 'C:\\Program Files\\7-Zip\\7z.exe';
        return [
          "$path = '" + path + "'",
          minVersion ? "$minimumVersion = [version]'" + minVersion + "'" : null,
          'if (Test-Path -Path $path) {',
          minVersion
            ? "    $fileVersion = try { [version]((Get-Item $path).VersionInfo.FileVersion -replace '[^\\d\\.].*$') } catch { $null }\n    if ($fileVersion -and $fileVersion -ge $minimumVersion) {\n        Write-Output \"Detected $path $fileVersion\"\n        exit 0\n    }"
            : '    Write-Output "Detected $path"\n    exit 0',
          '}',
          'exit 1'
        ].filter(Boolean).join('\n');
      }
      if (sel.method === 'msi') {
        const code = q(sel.code) || '{23170F69-40C1-2702-2301-000001000000}';
        return [
          "$productCode = '" + code + "'",
          '$keys = @(',
          '    "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\$productCode"',
          '    "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\$productCode"',
          ')',
          '$product = Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue | Select-Object -First 1',
          'if ($product) {',
          '    Write-Output "Detected $($product.DisplayName) $($product.DisplayVersion)"',
          '    exit 0',
          '}',
          'exit 1'
        ].join('\n');
      }
      const app = q(sel.app) || '7-Zip*';
      return ["$appName = '" + app + "'"]
        .concat(minVersion ? ["$minimumVersion = [version]'" + minVersion + "'"] : [])
        .concat(uninstallKeys(true))
        .concat([
          '$app = Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |',
          '    Where-Object { $_.DisplayName -like $appName } |',
          '    Select-Object -First 1'
        ])
        .concat(minVersion ? [
          '$detectedVersion = if ($app) {',
          "    try { [version]($app.DisplayVersion -replace '[^\\d\\.].*$') } catch { $null }",
          '}',
          'if ($app -and $detectedVersion -and $detectedVersion -ge $minimumVersion) {'
        ] : [
          'if ($app) {'
        ])
        .concat([
          '    Write-Output "Detected $($app.DisplayName) $($app.DisplayVersion)"',
          '    exit 0',
          '}',
          'exit 1'
        ]).join('\n');
    }
  });

  /* --------------------------------------------- detection and remediation */

  add({
    id: 'intune-remediation-service',
    title: 'Remediation: keep a service running',
    purposes: ['Intune', 'Compliance'],
    description: 'Detection and remediation pair that restarts a stopped service and can fix its startup type, for the agents that must never stay down.',
    requires: REQ_REMEDIATION,
    keywords: 'intune remediation proactive detection service stopped start-service startup type automatic restart agent',
    options: [
      { id: 'svc', label: 'Service name', type: 'text', placeholder: 'Spooler' },
      {
        id: 'fix', label: 'Remediation also', type: 'multi', items: [
          { id: 'auto', label: 'Set the startup type to automatic', default: true }
        ]
      },
      {
        id: 'output', label: 'Output', type: 'single', items: [
          { id: 'both', label: 'Detection + remediation', default: true },
          { id: 'detect', label: 'Detection script only' },
          { id: 'fix', label: 'Remediation script only' }
        ]
      }
    ],
    build: sel => {
      const svc = q(sel.svc) || 'Spooler';
      const detect = [
        "$serviceName = '" + svc + "'",
        '$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue',
        'if (-not $service) {',
        '    Write-Output "$serviceName is not installed"',
        '    exit 1',
        '}',
        "if ($service.Status -ne 'Running') {",
        '    Write-Output "$serviceName is $($service.Status)"',
        '    exit 1',
        '}',
        'Write-Output "$serviceName is running"',
        'exit 0'
      ];
      const fix = [
        "$serviceName = '" + svc + "'",
        sel.fix.has('auto') ? 'Set-Service -Name $serviceName -StartupType Automatic' : null,
        'Start-Service -Name $serviceName',
        '$service = Get-Service -Name $serviceName',
        "if ($service.Status -eq 'Running') {",
        '    Write-Output "$serviceName started"',
        '    exit 0',
        '}',
        'Write-Output "$serviceName is still $($service.Status)"',
        'exit 1'
      ].filter(Boolean);
      if (sel.output === 'detect') return detect.join('\n');
      if (sel.output === 'fix') return fix.join('\n');
      return [
        '# === Detection script, upload as Detect-' + settingName(svc) + '.ps1 ===',
        detect.join('\n'),
        '',
        '# === Remediation script, upload as Remediate-' + settingName(svc) + '.ps1 ===',
        fix.join('\n')
      ].join('\n');
    }
  });

  add({
    id: 'intune-remediation-process',
    title: 'Remediation: keep an application running',
    purposes: ['Intune', 'Compliance'],
    description: 'Detection and remediation pair that starts an executable again when its process is gone. For user applications, run the script in the logged-on user context.',
    requires: REQ_REMEDIATION,
    keywords: 'intune remediation process not running start-process restart application agent tray logged on user context',
    options: [
      { id: 'proc', label: 'Process name, without .exe', type: 'text', placeholder: 'MyAgent' },
      { id: 'path', label: 'Executable to start', type: 'text', placeholder: 'C:\\Program Files\\MyAgent\\MyAgent.exe' },
      { id: 'args', label: 'Arguments (optional)', type: 'text', placeholder: '/background' },
      {
        id: 'output', label: 'Output', type: 'single', items: [
          { id: 'both', label: 'Detection + remediation', default: true },
          { id: 'detect', label: 'Detection script only' },
          { id: 'fix', label: 'Remediation script only' }
        ]
      }
    ],
    build: sel => {
      const proc = q(sel.proc) || 'MyAgent';
      const path = q(sel.path) || 'C:\\Program Files\\MyAgent\\MyAgent.exe';
      const args = q(sel.args);
      const detect = [
        "$processName = '" + proc + "'",
        'if (Get-Process -Name $processName -ErrorAction SilentlyContinue) {',
        '    Write-Output "$processName is running"',
        '    exit 0',
        '}',
        'Write-Output "$processName is not running"',
        'exit 1'
      ];
      const fix = [
        "$path = '" + path + "'",
        'if (-not (Test-Path -Path $path)) {',
        '    Write-Output "$path not found"',
        '    exit 1',
        '}',
        'Start-Process -FilePath $path' + (args ? " -ArgumentList '" + args + "'" : ''),
        "Start-Sleep -Seconds 5",
        "if (Get-Process -Name '" + proc + "' -ErrorAction SilentlyContinue) {",
        '    Write-Output "started"',
        '    exit 0',
        '}',
        'Write-Output "failed to start"',
        'exit 1'
      ];
      if (sel.output === 'detect') return detect.join('\n');
      if (sel.output === 'fix') return fix.join('\n');
      return [
        '# === Detection script, upload as Detect-' + settingName(proc) + '.ps1 ===',
        detect.join('\n'),
        '',
        '# === Remediation script, upload as Remediate-' + settingName(proc) + '.ps1 ===',
        fix.join('\n')
      ].join('\n');
    }
  });

  add({
    id: 'intune-remediation-blocked-software',
    title: 'Remediation: remove forbidden software',
    purposes: ['Intune', 'Compliance', 'Cleanup'],
    description: 'Detects software that is not allowed in the estate and silently uninstalls it, using the MSI product code or the quiet uninstall string.',
    requires: REQ_REMEDIATION,
    keywords: 'intune remediation blocked forbidden software uninstall msiexec quietuninstallstring remove unwanted application',
    options: [
      { id: 'app', label: 'Application name (wildcards allowed)', type: 'text', placeholder: 'BadTool*' },
      {
        id: 'flags', label: 'Options', type: 'multi', items: [
          { id: 'userScope', label: 'Also search per-user installs', default: true }
        ]
      },
      {
        id: 'output', label: 'Output', type: 'single', items: [
          { id: 'both', label: 'Detection + remediation', default: true },
          { id: 'detect', label: 'Detection script only' },
          { id: 'fix', label: 'Remediation script only' }
        ]
      }
    ],
    build: sel => {
      const app = q(sel.app) || 'BadTool*';
      const keys = uninstallKeys(sel.flags.has('userScope'));
      const detect = ["$appName = '" + app + "'"]
        .concat(keys)
        .concat([
          '$apps = Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |',
          '    Where-Object { $_.DisplayName -like $appName }',
          'if ($apps) {',
          '    Write-Output "Found: $($apps.DisplayName -join \', \')"',
          '    exit 1',
          '}',
          'Write-Output "Not installed"',
          'exit 0'
        ]);
      const fix = ["$appName = '" + app + "'"]
        .concat(keys)
        .concat([
          '$apps = Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |',
          '    Where-Object { $_.DisplayName -like $appName }',
          'foreach ($app in $apps) {',
          "    if ($app.PSChildName -match '^\\{[0-9A-Fa-f-]+\\}$') {",
          '        Start-Process -FilePath msiexec.exe -ArgumentList "/x $($app.PSChildName) /qn /norestart" -Wait',
          '    }',
          '    elseif ($app.QuietUninstallString) {',
          '        Start-Process -FilePath cmd.exe -ArgumentList "/c $($app.QuietUninstallString)" -Wait',
          '    }',
          '    elseif ($app.UninstallString) {',
          '        # Best effort: many uninstallers accept /S or /quiet, verify per product.',
          '        Start-Process -FilePath cmd.exe -ArgumentList "/c $($app.UninstallString) /S" -Wait',
          '    }',
          '}',
          '$remaining = Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |',
          '    Where-Object { $_.DisplayName -like $appName }',
          'if ($remaining) {',
          '    Write-Output "Still installed: $($remaining.DisplayName -join \', \')"',
          '    exit 1',
          '}',
          'Write-Output "Removed"',
          'exit 0'
        ]);
      if (sel.output === 'detect') return detect.join('\n');
      if (sel.output === 'fix') return fix.join('\n');
      return [
        '# === Detection script, upload as Detect-BlockedSoftware.ps1 ===',
        detect.join('\n'),
        '',
        '# === Remediation script, upload as Remediate-BlockedSoftware.ps1 ===',
        fix.join('\n')
      ].join('\n');
    }
  });

  /* --------------------------------------------------------------- utility */

  add({
    id: 'intune-software-inventory',
    title: 'Installed software inventory',
    purposes: ['Intune', 'Reporting'],
    description: 'Lists everything installed on the device from the uninstall keys, with version, publisher and scope. Run it first to find the exact display name the checks above need.',
    requires: 'Run locally or through the Intune script blade. Reads the same registry keys the detection scripts use.',
    keywords: 'installed software inventory list displayname displayversion publisher uninstallstring registry audit find name',
    options: [
      { id: 'filter', label: 'Name contains (optional)', type: 'text', placeholder: 'zip' },
      {
        id: 'flags', label: 'Options', type: 'multi', items: [
          { id: 'userScope', label: 'Include per-user installs', default: true },
          { id: 'uninstall', label: 'Include the uninstall strings' }
        ]
      },
      {
        id: 'out', label: 'Output', type: 'single', items: [
          { id: 'table', label: 'Table (Format-Table)', default: true },
          { id: 'grid', label: 'Grid view (Out-GridView)' },
          { id: 'csv', label: 'CSV file (Export-Csv)' }
        ]
      }
    ],
    build: sel => {
      const filter = q(sel.filter);
      const cols = ['DisplayName', 'DisplayVersion', 'Publisher', 'InstallDate',
        "@{N='Scope';E={if ($_.PSPath -like '*HKEY_USERS*') { 'User' } else { 'Machine' }}}"];
      if (sel.flags.has('uninstall')) cols.push('UninstallString', 'QuietUninstallString');
      const lines = uninstallKeys(sel.flags.has('userScope')).concat([
        '$software = Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |',
        '    Where-Object { $_.DisplayName' + (filter ? " -like '*" + filter + "*'" : '') + ' } |',
        '    Select-Object ' + cols.join(', ') + ' |',
        '    Sort-Object DisplayName'
      ]);
      if (sel.out === 'csv') lines.push('$software | Export-Csv -Path .\\InstalledSoftware.csv -NoTypeInformation -Encoding UTF8');
      else if (sel.out === 'grid') lines.push("$software | Out-GridView -Title 'Installed software'");
      else lines.push('$software | Format-Table -AutoSize');
      return lines.join('\n');
    }
  });

  SCRIPTS_INTUNE.forEach(s => SCRIPTS.push(s));
})();

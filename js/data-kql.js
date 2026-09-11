'use strict';

/* ============================================================================
   Defender XDR / Sentinel hunting query library.

   Each spec is:
     { id, t, p: [purposes], d, k, days, ent, vars, opts, view, req, q }
   q(ctx) returns the query lines. ctx gives:
     ctx.ago            "ago(7d)" built from the chosen look back
     ctx.days           the number of days
     ctx.ent            the entity typed in the box (already escaped)
     ctx.where(col,op)  entity filter line, or null when the box is empty
     ctx.on(id)         is an option checkbox ticked
     ctx.n(id, def)     a numeric variable
     ctx.v(id)          a text variable
     ctx.view           the selected view id
   A row limit is appended automatically unless the spec sets noLimit.

   Table and column names follow the current advanced hunting schema.
   EntraIdSignInEvents replaces AADSignInEventsBeta; both work until the old
   table is retired.
   ========================================================================== */

(function () {
  const esc = v => String(v == null ? '' : v).trim().replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  const num = (v, d) => (parseInt(v, 10) > 0 ? parseInt(v, 10) : d);
  const REQ = 'Advanced hunting in the Microsoft Defender portal. Most of these tables also stream to Microsoft Sentinel.';

  function K(s) {
    const opts = [];
    opts.push({
      id: 'days', label: 'Look back (days)', type: 'number',
      placeholder: String(s.days || 7), value: String(s.days || 7),
      hint: 'Advanced hunting keeps 30 days of data.'
    });
    if (s.ent) opts.push({ id: 'entity', label: s.ent[0], type: 'text', placeholder: s.ent[1] });
    (s.vars || []).forEach(v => opts.push({
      id: v[0], label: v[1], type: v[3] || 'number', placeholder: v[2], value: v[2], hint: v[4]
    }));
    if (s.opts) {
      opts.push({
        id: 'opts', label: s.optsLabel || 'Options', type: 'multi', wide: s.opts.length > 4,
        items: s.opts.map(o => ({ id: o[0], label: o[1], default: !!o[2], hint: o[3] }))
      });
    }
    if (s.view) {
      opts.push({
        id: 'view', label: 'View', type: 'single',
        items: s.view.map((v, i) => ({ id: v[0], label: v[1], default: i === 0 }))
      });
    }
    opts.push({ id: 'limit', label: 'Row limit', type: 'number', placeholder: '100', value: '100', hint: 'Leave empty for no limit.' });

    function build(sel) {
      const ctx = {
        days: num(sel.days, s.days || 7),
        ent: esc(sel.entity),
        on: id => !!(sel.opts && sel.opts.has(id)),
        view: sel.view,
        v: id => esc(sel[id]),
        n: (id, d) => num(sel[id], d)
      };
      ctx.ago = 'ago(' + ctx.days + 'd)';
      ctx.where = (col, op) => (ctx.ent ? '| where ' + col + ' ' + (op || '=~') + ' "' + ctx.ent + '"' : null);
      const lines = [].concat(s.q(ctx)).filter(Boolean);
      const limit = num(sel.limit, 0);
      if (limit && !s.noLimit) lines.push('| take ' + limit);
      return lines.join('\n');
    }

    return {
      id: s.id,
      title: s.t,
      language: 'KQL',
      purposes: ['Hunting'].concat(s.p || []),
      description: s.d,
      requires: s.req || REQ,
      keywords: (s.k || '') + ' kql advanced hunting defender xdr sentinel query',
      options: opts,
      build: build
    };
  }

  const SPECS = [];
  const add = (...items) => items.forEach(i => SPECS.push(K(i)));

  const DEVICE = ['Device (optional)', 'PC-001'];
  const USER = ['User (optional)', 'jdoe@contoso.com'];

  /* ------------------------------------------- endpoint execution and LOLBins */

  add(
    {
      id: 'kql-lolbins',
      t: 'Living off the land binaries',
      p: ['Endpoint', 'Execution'],
      d: 'Signed Windows binaries that attackers use to download and run code, ranked so the rare combinations stand out.',
      k: 'lolbas lolbin certutil bitsadmin mshta regsvr32 wmic forfiles msiexec signed binary proxy execution t1218',
      days: 7, ent: DEVICE,
      opts: [['network', 'Only when the command line references a URL or IP', true], ['office', 'Only when started by an Office application', false]],
      view: [['detail', 'Every process'], ['summary', 'Count per binary and device']],
      q: ctx => [
        'let lolbins = dynamic(["certutil.exe","bitsadmin.exe","mshta.exe","regsvr32.exe","rundll32.exe","wscript.exe",',
        '    "cscript.exe","msiexec.exe","installutil.exe","regasm.exe","regsvcs.exe","msbuild.exe","curl.exe",',
        '    "forfiles.exe","pcalua.exe","wmic.exe","hh.exe","cmstp.exe","odbcconf.exe","xwizard.exe"]);',
        'DeviceProcessEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where FileName in~ (lolbins)',
        ctx.where('DeviceName', 'has'),
        ctx.on('network') ? '| where ProcessCommandLine matches regex @"https?://|\\\\\\\\\\d{1,3}(\\.\\d{1,3}){3}"' : null,
        ctx.on('office') ? '| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","msaccess.exe")' : null,
        ctx.view === 'summary'
          ? '| summarize Runs = count(), Devices = dcount(DeviceName), Commands = make_set(ProcessCommandLine, 5) by FileName\n| sort by Runs desc'
          : '| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine\n| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-encoded-powershell',
      t: 'Encoded and obfuscated PowerShell',
      p: ['Endpoint', 'Execution'],
      d: 'Base64 encoded commands, hidden windows and execution policy bypasses, with the payload decoded in the results.',
      k: 'powershell encodedcommand base64 hidden bypass frombase64string obfuscation iex invoke-expression t1059',
      days: 7, ent: DEVICE,
      opts: [['decode', 'Decode the base64 payload', true], ['hidden', 'Only hidden or bypass switches', false]],
      q: ctx => [
        'DeviceProcessEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where FileName in~ ("powershell.exe", "pwsh.exe", "powershell_ise.exe")',
        ctx.where('DeviceName', 'has'),
        '| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "-e ", "FromBase64String", "-w hidden", "-nop", "bypass", "IEX", "Invoke-Expression", "DownloadString")',
        ctx.on('hidden') ? '| where ProcessCommandLine has_any ("-w hidden", "-windowstyle hidden", "bypass")' : null,
        ctx.on('decode')
          ? '| extend Encoded = extract(@"(?i)-e(?:nc|ncodedcommand)?\\s+([A-Za-z0-9+/=]{20,})", 1, ProcessCommandLine)\n| extend Decoded = iff(isnotempty(Encoded), base64_decode_tostring(Encoded), "")\n| extend Decoded = replace_string(Decoded, "\\u0000", "")'
          : null,
        '| project Timestamp, DeviceName, AccountName, ProcessCommandLine' + (ctx.on('decode') ? ', Decoded' : '') + ', InitiatingProcessFileName',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-powershell-download',
      t: 'PowerShell downloading code',
      p: ['Endpoint', 'Execution', 'Network'],
      d: 'Download cradles in a command line, the step between a phishing document and the real payload.',
      k: 'downloadstring downloadfile invoke-webrequest iwr net.webclient bitstransfer curl wget cradle stager',
      days: 7, ent: DEVICE,
      q: ctx => [
        'DeviceProcessEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where ProcessCommandLine has_any ("DownloadString", "DownloadFile", "DownloadData", "Invoke-WebRequest", "iwr ",',
        '    "Net.WebClient", "Start-BitsTransfer", "curl ", "wget ", "Invoke-RestMethod")',
        ctx.where('DeviceName', 'has'),
        '| extend Url = extract(@"(https?://[^\\s]+)", 1, ProcessCommandLine)',
        '| project Timestamp, DeviceName, AccountName, FileName, Url, ProcessCommandLine, InitiatingProcessFileName',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-office-child-process',
      t: 'Office applications spawning shells',
      p: ['Endpoint', 'Execution', 'Phishing'],
      d: 'Word, Excel or Outlook launching a script host or shell, one of the highest fidelity signals of a malicious document.',
      k: 'winword excel outlook macro child process cmd powershell wscript maldoc initiating parent t1566',
      days: 7, ent: DEVICE,
      opts: [['pdf', 'Include PDF readers and archivers', false]],
      q: ctx => [
        'let officeApps = dynamic(["winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","msaccess.exe","mspub.exe","visio.exe"]);',
        ctx.on('pdf') ? 'let readers = dynamic(["acrord32.exe","foxitreader.exe","7z.exe","winrar.exe","winzip.exe"]);' : null,
        'let shells = dynamic(["cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","schtasks.exe"]);',
        'DeviceProcessEvents',
        '| where Timestamp > ' + ctx.ago,
        ctx.on('pdf')
          ? '| where InitiatingProcessFileName in~ (officeApps) or InitiatingProcessFileName in~ (readers)'
          : '| where InitiatingProcessFileName in~ (officeApps)',
        '| where FileName in~ (shells)',
        ctx.where('DeviceName', 'has'),
        '| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessCommandLine',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-execution-from-temp',
      t: 'Executables running from temporary folders',
      p: ['Endpoint', 'Execution'],
      d: 'Processes started from Temp, Downloads, AppData or the recycle bin, where legitimate software rarely lives.',
      k: 'appdata temp downloads programdata public recycle bin execution unusual path dropper staging',
      days: 7, ent: DEVICE,
      opts: [['unsigned', 'Only files without a valid signature', true], ['scripts', 'Include script files', false]],
      q: ctx => [
        'DeviceProcessEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where FolderPath has_any (@"\\AppData\\Local\\Temp", @"\\Downloads\\", @"\\ProgramData\\", @"\\Users\\Public\\", @"\\$Recycle.Bin", @"\\Windows\\Temp")',
        ctx.where('DeviceName', 'has'),
        ctx.on('scripts')
          ? '| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".ps1" or FileName endswith ".vbs" or FileName endswith ".js" or FileName endswith ".hta"'
          : '| where FileName endswith ".exe"',
        '| join kind=leftouter (DeviceFileCertificateInfo | where Timestamp > ' + ctx.ago + ' | distinct SHA1, IsSigned, IsTrusted, Signer) on $left.SHA1 == $right.SHA1',
        ctx.on('unsigned') ? '| where isempty(IsTrusted) or IsTrusted == false' : null,
        '| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, Signer, IsTrusted, SHA256',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-rundll32-suspicious',
      t: 'Suspicious rundll32 and regsvr32 use',
      p: ['Endpoint', 'Execution', 'Defence evasion'],
      d: 'Proxy execution through rundll32 and regsvr32, including the scriptlet and no-extension tricks.',
      k: 'rundll32 regsvr32 squiblydoo scrobj.dll javascript: url.dll shell32 proxy execution t1218.010',
      days: 7, ent: DEVICE,
      q: ctx => [
        'DeviceProcessEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where FileName in~ ("rundll32.exe", "regsvr32.exe")',
        ctx.where('DeviceName', 'has'),
        '| where ProcessCommandLine has_any ("javascript:", "vbscript:", "scrobj.dll", "http://", "https://", "\\\\\\\\", ".dat", ".log", ".txt", ".jpg", ".png")',
        '    or ProcessCommandLine matches regex @"(?i)rundll32(\\.exe)?\\s+[^,\\s]+\\s*$"',
        '| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-wmi-execution',
      t: 'Remote execution through WMI',
      p: ['Endpoint', 'Lateral movement'],
      d: 'Processes created by the WMI provider host, the fingerprint of wmic process call create and Invoke-WmiMethod.',
      k: 'wmiprvse wmic process call create invoke-wmimethod remote execution lateral movement t1047',
      days: 7, ent: DEVICE,
      q: ctx => [
        'DeviceProcessEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where InitiatingProcessFileName =~ "wmiprvse.exe" or ProcessCommandLine has_any ("process call create", "Invoke-WmiMethod", "Invoke-CimMethod")',
        ctx.where('DeviceName', 'has'),
        '| where not(FileName in~ ("wmiadap.exe", "wmiprvse.exe"))',
        '| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-scheduled-task-created',
      t: 'Scheduled task persistence',
      p: ['Endpoint', 'Persistence'],
      d: 'Task creation from both the process command line and the ScheduledTaskCreated event, filtered on tasks that point at user writable paths.',
      k: 'schtasks scheduledtaskcreated persistence at.exe register-scheduledtask task scheduler t1053.005',
      days: 14, ent: DEVICE,
      opts: [['suspicious', 'Only tasks that run from a user writable path', true]],
      q: ctx => [
        'union',
        '    (DeviceProcessEvents',
        '        | where Timestamp > ' + ctx.ago,
        '        | where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create"',
        '        | project Timestamp, DeviceName, AccountName, Source = "schtasks", Details = ProcessCommandLine, InitiatingProcessFileName),',
        '    (DeviceEvents',
        '        | where Timestamp > ' + ctx.ago,
        '        | where ActionType == "ScheduledTaskCreated"',
        '        | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, Source = "TaskCreatedEvent", Details = AdditionalFields, InitiatingProcessFileName)',
        ctx.where('DeviceName', 'has'),
        ctx.on('suspicious') ? '| where Details has_any (@"\\AppData\\", @"\\Temp\\", @"\\ProgramData\\", @"\\Public\\", "powershell", "mshta", "rundll32", "cmd.exe /c")' : null,
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-service-installed',
      t: 'New services installed',
      p: ['Endpoint', 'Persistence', 'Lateral movement'],
      d: 'Service installation events and sc.exe create commands, which is how PsExec and many implants land.',
      k: 'serviceinstalled sc.exe create new-service psexec persistence lateral movement t1543.003 imagepath',
      days: 14, ent: DEVICE,
      opts: [['suspicious', 'Only services running from an unusual path', true]],
      q: ctx => [
        'union',
        '    (DeviceEvents',
        '        | where Timestamp > ' + ctx.ago,
        '        | where ActionType == "ServiceInstalled"',
        '        | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, Source = "ServiceInstalled", Details = AdditionalFields),',
        '    (DeviceProcessEvents',
        '        | where Timestamp > ' + ctx.ago,
        '        | where (FileName =~ "sc.exe" and ProcessCommandLine has " create") or ProcessCommandLine has "New-Service"',
        '        | project Timestamp, DeviceName, AccountName, Source = "sc.exe", Details = ProcessCommandLine)',
        ctx.where('DeviceName', 'has'),
        ctx.on('suspicious') ? '| where Details has_any (@"\\Temp\\", @"\\AppData\\", @"\\ProgramData\\", @"\\Users\\", "powershell", "cmd.exe", ".bat", ".vbs")' : null,
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-run-key-persistence',
      t: 'Registry autorun persistence',
      p: ['Endpoint', 'Persistence'],
      d: 'Values written to Run, RunOnce and Winlogon keys, the most common persistence location on Windows.',
      k: 'registryvalueset run runonce winlogon shell userinit autorun persistence t1547.001 registry',
      days: 14, ent: DEVICE,
      opts: [['scripts', 'Only values that reference a script or a user path', true]],
      q: ctx => [
        'DeviceRegistryEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")',
        '| where RegistryKey has_any (@"\\CurrentVersion\\Run", @"\\CurrentVersion\\RunOnce", @"\\Winlogon", @"\\CurrentVersion\\Explorer\\User Shell Folders",',
        '    @"\\CurrentVersion\\Policies\\Explorer\\Run", @"\\Image File Execution Options", @"\\CurrentVersion\\AppInit_DLLs")',
        ctx.where('DeviceName', 'has'),
        ctx.on('scripts') ? '| where RegistryValueData has_any (@"\\AppData\\", @"\\Temp\\", @"\\ProgramData\\", @"\\Public\\", "powershell", "mshta", "wscript", "cscript", "rundll32", "http")' : null,
        '| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-startup-folder',
      t: 'Startup folder and shortcut persistence',
      p: ['Endpoint', 'Persistence'],
      d: 'Files and shortcuts dropped into a Startup folder, including the shell link creation event.',
      k: 'startup folder lnk shortcut shelllinkcreatefileevent persistence t1547.001 autostart drop',
      days: 14, ent: DEVICE,
      q: ctx => [
        'union',
        '    (DeviceFileEvents',
        '        | where Timestamp > ' + ctx.ago,
        '        | where FolderPath has @"\\Start Menu\\Programs\\Startup"',
        '        | project Timestamp, DeviceName, Account = InitiatingProcessAccountName, Source = "FileDrop", FileName, FolderPath, InitiatingProcessFileName),',
        '    (DeviceEvents',
        '        | where Timestamp > ' + ctx.ago,
        '        | where ActionType == "ShellLinkCreateFileEvent"',
        '        | project Timestamp, DeviceName, Account = InitiatingProcessAccountName, Source = "ShellLink", FileName, FolderPath, InitiatingProcessFileName)',
        ctx.where('DeviceName', 'has'),
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-lsass-access',
      t: 'Credential dumping from LSASS',
      p: ['Endpoint', 'Credential access'],
      d: 'Processes opening a handle to lsass.exe or writing a memory dump, filtered down to the unexpected callers.',
      k: 'lsass mimikatz procdump comsvcs minidump openprocess credential dumping t1003.001 sekurlsa',
      days: 7, ent: DEVICE,
      q: ctx => [
        'let expected = dynamic(["MsMpEng.exe","MsSense.exe","SenseIR.exe","csrss.exe","wininit.exe","services.exe","taskmgr.exe","lsass.exe","svchost.exe"]);',
        'union',
        '    (DeviceEvents',
        '        | where Timestamp > ' + ctx.ago,
        '        | where ActionType in ("OpenProcessApiCall", "ReadProcessMemoryApiCall")',
        '        | where FileName =~ "lsass.exe"',
        '        | where not(InitiatingProcessFileName in~ (expected))',
        '        | project Timestamp, DeviceName, Source = ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName),',
        '    (DeviceProcessEvents',
        '        | where Timestamp > ' + ctx.ago,
        '        | where ProcessCommandLine has_any ("lsass", "MiniDump", "comsvcs.dll", "sekurlsa", "procdump")',
        '        | project Timestamp, DeviceName, Source = "CommandLine", InitiatingProcessFileName = FileName, InitiatingProcessCommandLine = ProcessCommandLine, InitiatingProcessAccountName = AccountName)',
        ctx.where('DeviceName', 'has'),
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-shadow-copy-deletion',
      t: 'Shadow copy and backup destruction',
      p: ['Endpoint', 'Ransomware'],
      d: 'vssadmin, wbadmin and bcdedit commands that destroy recovery options, which almost always precede encryption.',
      k: 'vssadmin delete shadows wbadmin bcdedit recoveryenabled ransomware backup destruction t1490 wmic shadowcopy',
      days: 7, ent: DEVICE,
      q: ctx => [
        'DeviceProcessEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_all ("delete", "shadows"))',
        '    or (FileName =~ "wbadmin.exe" and ProcessCommandLine has "delete")',
        '    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any ("recoveryenabled no", "bootstatuspolicy ignoreallfailures"))',
        '    or (FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy delete")',
        '    or ProcessCommandLine has "Remove-Item -Path C:\\\\Windows\\\\System32\\\\config"',
        ctx.where('DeviceName', 'has'),
        '| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-defender-tampering',
      t: 'Defender tampering and exclusions',
      p: ['Endpoint', 'Defence evasion'],
      d: 'Attempts to disable protection or add exclusions, from both the tampering event and the command line.',
      k: 'tamperingattempt set-mppreference exclusionpath disablerealtimemonitoring defender disabled evasion t1562.001',
      days: 14, ent: DEVICE,
      q: ctx => [
        'union',
        '    (DeviceEvents',
        '        | where Timestamp > ' + ctx.ago,
        '        | where ActionType in ("TamperingAttempt", "AntivirusScanCancelled", "ExploitGuardNonMicrosoftSignedBlocked")',
        '        | project Timestamp, DeviceName, Account = InitiatingProcessAccountName, Source = ActionType, Details = AdditionalFields, InitiatingProcessFileName),',
        '    (DeviceProcessEvents',
        '        | where Timestamp > ' + ctx.ago,
        '        | where ProcessCommandLine has_any ("Set-MpPreference", "Add-MpPreference", "DisableRealtimeMonitoring", "DisableBehaviorMonitoring",',
        '            "DisableIOAVProtection", "ExclusionPath", "ExclusionProcess", "ExclusionExtension", "sc stop WinDefend", "MpCmdRun.exe -RemoveDefinitions")',
        '        | project Timestamp, DeviceName, Account = AccountName, Source = "CommandLine", Details = ProcessCommandLine, InitiatingProcessFileName)',
        ctx.where('DeviceName', 'has'),
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-security-log-cleared',
      t: 'Event logs cleared',
      p: ['Endpoint', 'Anti-forensics'],
      d: 'Log clearing through the security event, wevtutil or PowerShell, which is rare enough that every hit deserves a look.',
      k: 'securitylogcleared wevtutil clear-eventlog cl clear log anti forensics t1070.001 evidence destruction',
      days: 30, ent: DEVICE,
      q: ctx => [
        'union',
        '    (DeviceEvents',
        '        | where Timestamp > ' + ctx.ago,
        '        | where ActionType == "SecurityLogCleared"',
        '        | project Timestamp, DeviceName, Account = InitiatingProcessAccountName, Source = "SecurityLogCleared", Details = AdditionalFields),',
        '    (DeviceProcessEvents',
        '        | where Timestamp > ' + ctx.ago,
        '        | where ProcessCommandLine has_any ("wevtutil cl", "wevtutil clear-log", "Clear-EventLog", "Remove-EventLog", "fsutil usn deletejournal")',
        '        | project Timestamp, DeviceName, Account = AccountName, Source = "CommandLine", Details = ProcessCommandLine)',
        ctx.where('DeviceName', 'has'),
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-local-account-created',
      t: 'Local accounts and admin group changes',
      p: ['Endpoint', 'Persistence', 'Privilege escalation'],
      d: 'Accounts created on a device and users added to the local administrators group, from events and command lines.',
      k: 'useraccountcreated useraccountaddedtolocalgroup net user add net localgroup administrators backdoor account',
      days: 14, ent: DEVICE,
      q: ctx => [
        'union',
        '    (DeviceEvents',
        '        | where Timestamp > ' + ctx.ago,
        '        | where ActionType in ("UserAccountCreated", "UserAccountAddedToLocalGroup", "SecurityGroupCreated", "UserAccountModified")',
        '        | project Timestamp, DeviceName, Account = AccountName, Source = ActionType, Details = AdditionalFields, InitiatingProcessCommandLine),',
        '    (DeviceProcessEvents',
        '        | where Timestamp > ' + ctx.ago,
        '        | where ProcessCommandLine has_any ("net user ", "net1 user ", "net localgroup administrators", "New-LocalUser", "Add-LocalGroupMember")',
        '        | project Timestamp, DeviceName, Account = AccountName, Source = "CommandLine", Details = ProcessCommandLine, InitiatingProcessCommandLine)',
        ctx.where('DeviceName', 'has'),
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-dll-sideloading',
      t: 'DLL sideloading candidates',
      p: ['Endpoint', 'Defence evasion'],
      d: 'Signed executables loading an unsigned DLL from a user writable folder, the classic sideloading pattern.',
      k: 'dll sideloading hijacking imageload unsigned appdata search order t1574.002 planted dll',
      days: 7, ent: DEVICE,
      q: ctx => [
        'DeviceImageLoadEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where FolderPath has_any (@"\\AppData\\", @"\\Temp\\", @"\\ProgramData\\", @"\\Users\\Public\\", @"\\Downloads\\")',
        '| where FileName endswith ".dll"',
        ctx.where('DeviceName', 'has'),
        '| join kind=leftouter (DeviceFileCertificateInfo | where Timestamp > ' + ctx.ago + ' | distinct SHA1, IsTrusted, Signer) on $left.SHA1 == $right.SHA1',
        '| where isempty(IsTrusted) or IsTrusted == false',
        '| summarize Loads = count(), Devices = dcount(DeviceName), Loaders = make_set(InitiatingProcessFileName, 5) by FileName, FolderPath, SHA256',
        '| sort by Loads desc'
      ]
    },
    {
      id: 'kql-msbuild-and-compilers',
      t: 'Compilers and trusted developer tools',
      p: ['Endpoint', 'Defence evasion'],
      d: 'MSBuild, InstallUtil, csc and friends running outside a development context, a well known way to run code past allow lists.',
      k: 'msbuild installutil regasm regsvcs csc.exe jsc.exe trusted developer utilities t1127 inline task',
      days: 14, ent: DEVICE,
      q: ctx => [
        'DeviceProcessEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where FileName in~ ("msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "csc.exe", "vbc.exe", "jsc.exe", "ilasm.exe")',
        ctx.where('DeviceName', 'has'),
        '| where not(InitiatingProcessFileName in~ ("devenv.exe", "msbuild.exe", "dotnet.exe", "vbcscompiler.exe", "cmd.exe"))',
        '    or ProcessCommandLine has_any (@"\\AppData\\", @"\\Temp\\", @"\\ProgramData\\", ".xml", ".csproj")',
        '| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-archive-staging',
      t: 'Data staged into archives',
      p: ['Endpoint', 'Exfiltration'],
      d: 'Archive tools invoked with a password or against a user profile, which is how data gets packaged before it leaves.',
      k: 'rar 7z winrar zip password staging collection archive exfiltration t1560 compress-archive',
      days: 14, ent: DEVICE,
      q: ctx => [
        'DeviceProcessEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where FileName in~ ("rar.exe", "7z.exe", "7za.exe", "winrar.exe", "zip.exe", "tar.exe", "makecab.exe")',
        '    or ProcessCommandLine has_any ("Compress-Archive", "-hp", " a -r ")',
        ctx.where('DeviceName', 'has'),
        '| extend HasPassword = ProcessCommandLine matches regex @"(?i)\\s-(hp|p)\\S+"',
        '| project Timestamp, DeviceName, AccountName, FileName, HasPassword, ProcessCommandLine, InitiatingProcessFileName',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-remote-access-tools',
      t: 'Remote access tools appearing',
      p: ['Endpoint', 'Command and control'],
      d: 'AnyDesk, TeamViewer, ScreenConnect, ngrok and similar tools, which attackers install as a cheap and quiet backdoor.',
      k: 'anydesk teamviewer screenconnect atera splashtop ngrok rmm remote access tool unauthorised t1219',
      days: 30, ent: DEVICE,
      view: [['detail', 'Every execution'], ['summary', 'Count per tool and device']],
      q: ctx => [
        'let tools = dynamic(["anydesk.exe","teamviewer.exe","tvnserver.exe","screenconnect.clientservice.exe","connectwisecontrol.client.exe",',
        '    "atera_agent.exe","splashtop.exe","ngrok.exe","rustdesk.exe","supremo.exe","ammyy.exe","logmein.exe","gotoassist.exe","dwagent.exe"]);',
        'DeviceProcessEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where FileName in~ (tools) or ProcessCommandLine has_any ("ngrok", "anydesk", "rustdesk", "screenconnect")',
        ctx.where('DeviceName', 'has'),
        ctx.view === 'summary'
          ? '| summarize Runs = count(), Devices = dcount(DeviceName), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by FileName\n| sort by Runs desc'
          : '| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine\n| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-usb-and-removable',
      t: 'USB and removable media use',
      p: ['Endpoint', 'Exfiltration', 'Insider risk'],
      d: 'Devices mounted and the files written to them, the simplest exfiltration route there is.',
      k: 'usbdrivemounted pnpdeviceconnected removable media copy to usb exfiltration insider data theft',
      days: 30, ent: DEVICE,
      opts: [['files', 'Include files written to removable drives', true]],
      q: ctx => [
        'union',
        '    (DeviceEvents',
        '        | where Timestamp > ' + ctx.ago,
        '        | where ActionType in ("UsbDriveMounted", "UsbDriveUnmounted", "PnpDeviceConnected")',
        '        | project Timestamp, DeviceName, Account = InitiatingProcessAccountName, Source = ActionType, Details = AdditionalFields, FileName = "", FolderPath = "")',
        ctx.on('files')
          ? ',\n    (DeviceFileEvents\n        | where Timestamp > ' + ctx.ago + '\n        | where ActionType == "FileCreated"\n        | where FolderPath matches regex @"^[D-Z]:\\\\\\\\" and not(FolderPath startswith "C:")\n        | project Timestamp, DeviceName, Account = InitiatingProcessAccountName, Source = "FileWritten", Details = "", FileName, FolderPath)'
          : null,
        ctx.where('DeviceName', 'has'),
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-asr-and-blocks',
      t: 'Attack surface reduction blocks',
      p: ['Endpoint', 'Triage'],
      d: 'What the ASR rules, exploit protection and network protection actually blocked, grouped so patterns are visible.',
      k: 'asr attack surface reduction blocked exploitguard networkprotection smartscreen audited rules t1562',
      days: 7, ent: DEVICE,
      view: [['summary', 'Count per rule and device'], ['detail', 'Every block']],
      q: ctx => [
        'DeviceEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where ActionType startswith "Asr" or ActionType startswith "ExploitGuard" or ActionType has "SmartScreen"',
        ctx.where('DeviceName', 'has'),
        ctx.view === 'detail'
          ? '| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl\n| sort by Timestamp desc'
          : '| summarize Blocks = count(), Devices = dcount(DeviceName), Files = make_set(FileName, 5) by ActionType\n| sort by Blocks desc'
      ]
    },
    {
      id: 'kql-antivirus-detections',
      t: 'Antivirus detections and their source',
      p: ['Endpoint', 'Triage'],
      d: 'Malware detections with the process that dropped the file, which usually explains how it arrived.',
      k: 'antivirusdetection antivirusreport malware detection threat name remediation quarantine defender av',
      days: 14, ent: DEVICE,
      view: [['detail', 'Every detection'], ['summary', 'Count per threat']],
      q: ctx => [
        'DeviceEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where ActionType startswith "Antivirus"',
        ctx.where('DeviceName', 'has'),
        '| extend Threat = tostring(parse_json(AdditionalFields).ThreatName)',
        ctx.view === 'summary'
          ? '| summarize Detections = count(), Devices = dcount(DeviceName), Files = make_set(FileName, 5) by Threat, ActionType\n| sort by Detections desc'
          : '| project Timestamp, DeviceName, ActionType, Threat, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine\n| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-first-seen-process',
      t: 'Processes seen for the first time',
      p: ['Endpoint', 'Execution'],
      d: 'Binaries that appeared in the last day but never in the weeks before, a cheap novelty detection.',
      k: 'first time seen new binary novelty rare prevalence baseline anomaly unique hash never before',
      days: 30,
      vars: [['recent', 'Treat as new if first seen within (days)', '1']],
      q: ctx => [
        'let recent = ' + ctx.n('recent', 1) + 'd;',
        'DeviceProcessEvents',
        '| where Timestamp > ' + ctx.ago,
        '| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Runs = count(), Devices = dcount(DeviceName),',
        '    Commands = make_set(ProcessCommandLine, 3) by FileName, SHA256',
        '| where FirstSeen > ago(recent)',
        '| sort by Runs asc, FirstSeen desc'
      ]
    },
    {
      id: 'kql-rare-process-prevalence',
      t: 'Rare processes across the estate',
      p: ['Endpoint', 'Execution'],
      d: 'Executables that only ever ran on one or two machines, which is where targeted tooling hides.',
      k: 'prevalence rare uncommon few devices unique binary outlier hunting baseline dcount',
      days: 30,
      vars: [['max', 'Maximum devices', '2']],
      q: ctx => [
        'DeviceProcessEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where isnotempty(SHA256)',
        '| summarize Devices = dcount(DeviceName), Runs = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),',
        '    Paths = make_set(FolderPath, 3), Accounts = make_set(AccountName, 3) by FileName, SHA256',
        '| where Devices <= ' + ctx.n('max', 2),
        '| sort by LastSeen desc'
      ]
    }
  );

  /* ------------------------------- network, command and control, lateral movement */

  add(
    {
      id: 'kql-beaconing',
      t: 'Beaconing to a command and control server',
      p: ['Network', 'Command and control'],
      d: 'Finds connections that repeat on a near constant interval, the timing fingerprint of an implant checking in.',
      k: 'beacon interval jitter c2 command and control periodic connection stddev heartbeat cobalt strike',
      days: 3, ent: DEVICE,
      vars: [['min', 'Minimum connections', '20'], ['jitter', 'Maximum interval spread in seconds', '30']],
      q: ctx => [
        'DeviceNetworkEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where ActionType == "ConnectionSuccess" and RemoteIPType == "Public"',
        ctx.where('DeviceName', 'has'),
        '| sort by DeviceName asc, RemoteIP asc, Timestamp asc',
        '| extend PreviousTime = prev(Timestamp), PreviousIP = prev(RemoteIP), PreviousDevice = prev(DeviceName)',
        '| where RemoteIP == PreviousIP and DeviceName == PreviousDevice',
        '| extend Delta = datetime_diff("second", Timestamp, PreviousTime)',
        '| summarize Connections = count(), AvgInterval = avg(Delta), Spread = stdev(Delta),',
        '    Ports = make_set(RemotePort, 5), Processes = make_set(InitiatingProcessFileName, 5) by DeviceName, RemoteIP',
        '| where Connections >= ' + ctx.n('min', 20) + ' and Spread < ' + ctx.n('jitter', 30) + ' and AvgInterval > 5',
        '| sort by Connections desc'
      ]
    },
    {
      id: 'kql-rare-external-destinations',
      t: 'Rarely contacted external destinations',
      p: ['Network', 'Command and control'],
      d: 'External domains reached by only one or two devices in the whole estate, ranked by how new they are.',
      k: 'rare domain prevalence first seen unusual destination remoteurl outlier newly observed c2',
      days: 14,
      vars: [['max', 'Maximum devices', '2']],
      q: ctx => [
        'DeviceNetworkEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where isnotempty(RemoteUrl) and RemoteIPType == "Public"',
        '| summarize Devices = dcount(DeviceName), Connections = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),',
        '    Processes = make_set(InitiatingProcessFileName, 5), DeviceList = make_set(DeviceName, 5) by RemoteUrl',
        '| where Devices <= ' + ctx.n('max', 2),
        '| sort by FirstSeen desc'
      ]
    },
    {
      id: 'kql-network-from-script-hosts',
      t: 'Script hosts talking to the internet',
      p: ['Network', 'Execution'],
      d: 'Outbound connections made by PowerShell, cmd, mshta, rundll32 and friends, which normal workstations rarely need.',
      k: 'powershell mshta rundll32 wscript outbound connection script host internet c2 download',
      days: 7, ent: DEVICE,
      q: ctx => [
        'let interpreters = dynamic(["powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe",',
        '    "regsvr32.exe","certutil.exe","bitsadmin.exe","msbuild.exe","installutil.exe","curl.exe"]);',
        'DeviceNetworkEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where InitiatingProcessFileName in~ (interpreters)',
        '| where RemoteIPType == "Public"',
        ctx.where('DeviceName', 'has'),
        '| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-anonymisers-and-tunnels',
      t: 'Tor, tunnels and anonymisers',
      p: ['Network', 'Command and control', 'Defence evasion'],
      d: 'Connections to Tor, ngrok, cloudflared and similar tunnelling services, which are almost never business traffic.',
      k: 'tor ngrok cloudflared localtunnel serveo anonymiser vpn tunnel proxy evasion egress',
      days: 14, ent: DEVICE,
      q: ctx => [
        'let indicators = dynamic(["torproject","ngrok.io","ngrok-free","trycloudflare","cloudflared","localtunnel","serveo.net",',
        '    "portmap.io","pagekite","tunnelto.dev","loca.lt","onion.","zerotier","tailscale"]);',
        'DeviceNetworkEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where RemoteUrl has_any (indicators) or RemotePort in (9001, 9030, 9050, 9051, 9150)',
        ctx.where('DeviceName', 'has'),
        '| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-paste-and-code-hosting',
      t: 'Payload hosting and paste sites',
      p: ['Network', 'Command and control'],
      d: 'Traffic to pastebin, raw GitHub, Discord and Telegram content delivery, common staging and exfiltration hosts.',
      k: 'pastebin raw.githubusercontent discord cdn telegram transfer.sh anonfiles payload staging exfil url',
      days: 14, ent: DEVICE,
      q: ctx => [
        'let hosts = dynamic(["pastebin.com","paste.ee","hastebin","ghostbin","raw.githubusercontent.com","gist.githubusercontent.com",',
        '    "cdn.discordapp.com","media.discordapp.net","api.telegram.org","transfer.sh","anonfiles","file.io","temp.sh","0x0.st","bashupload"]);',
        'DeviceNetworkEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where RemoteUrl has_any (hosts)',
        ctx.where('DeviceName', 'has'),
        '| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-cloud-storage-uploads',
      t: 'Uploads to personal cloud storage',
      p: ['Network', 'Exfiltration', 'Insider risk'],
      d: 'Endpoint connections to consumer file sharing services, the usual route for data walking out of a managed device.',
      k: 'dropbox mega wetransfer google drive personal onedrive box exfiltration upload consumer storage insider',
      days: 14, ent: DEVICE,
      view: [['summary', 'Count per device and service'], ['detail', 'Every connection']],
      q: ctx => [
        'let services = dynamic(["dropbox.com","mega.nz","mega.io","wetransfer.com","drive.google.com","docs.google.com",',
        '    "box.com","pcloud.com","sync.com","icedrive","4shared","sendspace","filemail","smash.gg"]);',
        'DeviceNetworkEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where RemoteUrl has_any (services)',
        ctx.where('DeviceName', 'has'),
        ctx.view === 'detail'
          ? '| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteUrl\n| sort by Timestamp desc'
          : '| summarize Connections = count(), Users = make_set(InitiatingProcessAccountName, 5), Apps = make_set(InitiatingProcessFileName, 5),\n    LastSeen = max(Timestamp) by DeviceName, RemoteUrl\n| sort by Connections desc'
      ]
    },
    {
      id: 'kql-dns-anomalies',
      t: 'Long or unusual DNS queries',
      p: ['Network', 'Exfiltration'],
      d: 'Very long host names and high subdomain counts, the shape of DNS tunnelling and beacon domains.',
      k: 'dns tunnelling long hostname subdomain entropy dnsqueryresponse exfiltration over dns t1071.004',
      days: 7, ent: DEVICE,
      vars: [['len', 'Minimum host name length', '50']],
      q: ctx => [
        'DeviceNetworkEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where isnotempty(RemoteUrl)',
        ctx.where('DeviceName', 'has'),
        '| extend Host = tostring(split(RemoteUrl, "/")[0])',
        '| extend Parts = split(Host, "."), Labels = array_length(split(Host, "."))',
        '| where strlen(Host) >= ' + ctx.n('len', 50) + ' or Labels >= 5',
        '| extend Domain = strcat(tostring(Parts[Labels - 2]), ".", tostring(Parts[Labels - 1]))',
        '| summarize Queries = count(), Devices = dcount(DeviceName), Sample = any(Host), MaxLength = max(strlen(Host)) by Domain',
        '| sort by Queries desc'
      ]
    },
    {
      id: 'kql-smb-lateral-movement',
      t: 'SMB connections to many hosts',
      p: ['Network', 'Lateral movement'],
      d: 'One device opening SMB sessions to an unusual number of peers, which is what tool driven lateral movement looks like.',
      k: 'smb 445 lateral movement admin share fan out many hosts spread wmiexec psexec copy',
      days: 7, ent: DEVICE,
      vars: [['min', 'Minimum distinct destinations', '10']],
      q: ctx => [
        'DeviceNetworkEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where RemotePort in (445, 139) and ActionType == "ConnectionSuccess"',
        ctx.where('DeviceName', 'has'),
        '| summarize Destinations = dcount(RemoteIP), Connections = count(), Targets = make_set(RemoteIP, 20),',
        '    Processes = make_set(InitiatingProcessFileName, 5), Accounts = make_set(InitiatingProcessAccountName, 5) by DeviceName, bin(Timestamp, 1h)',
        '| where Destinations >= ' + ctx.n('min', 10),
        '| sort by Destinations desc'
      ]
    },
    {
      id: 'kql-remote-management-protocols',
      t: 'WinRM, RPC and remote service execution',
      p: ['Network', 'Lateral movement'],
      d: 'Connections on the remote management ports together with the process that made them, so PsExec style movement stands out.',
      k: 'winrm 5985 5986 rpc 135 psexec wmiexec remote execution lateral movement admin tooling',
      days: 7, ent: DEVICE,
      q: ctx => [
        'DeviceNetworkEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where RemotePort in (135, 5985, 5986, 47001) and ActionType == "ConnectionSuccess"',
        ctx.where('DeviceName', 'has'),
        '| where not(InitiatingProcessFileName in~ ("svchost.exe", "MsSense.exe", "SenseNdr.exe"))',
        '| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-rdp-connections',
      t: 'RDP sessions and their source',
      p: ['Network', 'Lateral movement'],
      d: 'Remote interactive logons with the source address, split between internal and external origins.',
      k: 'rdp remoteinteractive 3389 remotedesktopconnection logon source external exposed jump host',
      days: 7, ent: DEVICE,
      opts: [['external', 'Only sessions from outside the corporate ranges', false]],
      q: ctx => [
        'DeviceLogonEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where LogonType == "RemoteInteractive" and ActionType == "LogonSuccess"',
        ctx.where('DeviceName', 'has'),
        ctx.on('external')
          ? '| where isnotempty(RemoteIP) and not(ipv4_is_private(RemoteIP))'
          : null,
        '| summarize Sessions = count(), Sources = make_set(RemoteIP, 10), Devices = make_set(DeviceName, 10),',
        '    FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by AccountName, AccountDomain',
        '| sort by Sessions desc'
      ]
    },
    {
      id: 'kql-port-scanning',
      t: 'Port scanning from a device',
      p: ['Network', 'Discovery'],
      d: 'A single host touching many ports or many addresses in a short window, which is what internal scanning looks like.',
      k: 'port scan discovery nmap sweep many ports failed connections reconnaissance internal scanning',
      days: 3, ent: DEVICE,
      vars: [['ports', 'Minimum distinct ports', '50']],
      q: ctx => [
        'DeviceNetworkEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where ActionType in ("ConnectionFailed", "ConnectionRequest", "ConnectionSuccess")',
        ctx.where('DeviceName', 'has'),
        '| summarize Ports = dcount(RemotePort), Hosts = dcount(RemoteIP), Attempts = count(),',
        '    Processes = make_set(InitiatingProcessFileName, 5) by DeviceName, bin(Timestamp, 10m)',
        '| where Ports >= ' + ctx.n('ports', 50) + ' or Hosts >= 100',
        '| sort by Ports desc'
      ]
    },
    {
      id: 'kql-new-listening-ports',
      t: 'New listening ports on devices',
      p: ['Network', 'Persistence'],
      d: 'Listening sockets opened by unexpected processes, which can be a backdoor or an unapproved service.',
      k: 'listeningconnectioncreated listening port bind backdoor service exposed socket server',
      days: 7, ent: DEVICE,
      q: ctx => [
        'DeviceNetworkEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where ActionType == "ListeningConnectionCreated"',
        ctx.where('DeviceName', 'has'),
        '| where not(InitiatingProcessFileName in~ ("svchost.exe", "System", "services.exe", "lsass.exe", "spoolsv.exe", "MsSense.exe"))',
        '| summarize Devices = dcount(DeviceName), Events = count(), DeviceList = make_set(DeviceName, 10),',
        '    FirstSeen = min(Timestamp) by InitiatingProcessFileName, LocalPort',
        '| sort by FirstSeen desc'
      ]
    },
    {
      id: 'kql-discovery-commands',
      t: 'Host and domain discovery commands',
      p: ['Endpoint', 'Discovery'],
      d: 'The reconnaissance one liners an operator runs in the first minutes on a host, grouped per device.',
      k: 'whoami net group domain admins nltest systeminfo ipconfig quser tasklist discovery t1087 recon',
      days: 7, ent: DEVICE,
      vars: [['min', 'Minimum distinct commands per device', '3']],
      q: ctx => [
        'let recon = dynamic(["whoami","net group","net localgroup","net user","net view","net share","nltest","dsquery",',
        '    "systeminfo","ipconfig /all","arp -a","route print","quser","qwinsta","tasklist","netstat -ano","wmic computersystem"]);',
        'DeviceProcessEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where ProcessCommandLine has_any (recon)',
        ctx.where('DeviceName', 'has'),
        '| summarize Commands = dcount(ProcessCommandLine), Runs = count(), Samples = make_set(ProcessCommandLine, 10),',
        '    Accounts = make_set(AccountName, 5), Window = max(Timestamp) - min(Timestamp) by DeviceName, bin(Timestamp, 1h)',
        '| where Commands >= ' + ctx.n('min', 3),
        '| sort by Commands desc'
      ]
    },
    {
      id: 'kql-recon-tooling',
      t: 'Known reconnaissance tooling',
      p: ['Endpoint', 'Discovery', 'Credential access'],
      d: 'Named offensive tools such as SharpHound, AdFind, Rubeus and Seatbelt, matched on file name and on command line.',
      k: 'sharphound bloodhound adfind rubeus seatbelt mimikatz certify powerview nishang tooling attack framework',
      days: 30, ent: DEVICE,
      q: ctx => [
        'let tools = dynamic(["sharphound","bloodhound","adfind","rubeus","seatbelt","mimikatz","certify","powerview","powerup",',
        '    "winpeas","lazagne","nishang","koadic","sharpview","sharpup","kerbrute","impacket","crackmapexec","netexec","sliver","havoc"]);',
        'union',
        '    (DeviceProcessEvents',
        '        | where Timestamp > ' + ctx.ago,
        '        | where FileName has_any (tools) or ProcessCommandLine has_any (tools)',
        '        | project Timestamp, DeviceName, Account = AccountName, Source = "Process", Name = FileName, Details = ProcessCommandLine),',
        '    (DeviceFileEvents',
        '        | where Timestamp > ' + ctx.ago,
        '        | where FileName has_any (tools)',
        '        | project Timestamp, DeviceName, Account = InitiatingProcessAccountName, Source = "File", Name = FileName, Details = FolderPath)',
        ctx.where('DeviceName', 'has'),
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-credential-file-access',
      t: 'Access to credential files',
      p: ['Endpoint', 'Credential access'],
      d: 'Reads of browser credential stores, password manager databases, unattend files and private keys.',
      k: 'login data kdbx unattend.xml sysprep id_rsa .ppk credentials browser password store t1552 secrets',
      days: 14, ent: DEVICE,
      q: ctx => [
        'let targets = dynamic(["Login Data","Cookies","key3.db","key4.db","logins.json",".kdbx",".kdb","unattend.xml","sysprep.inf",',
        '    "id_rsa",".ppk","credentials.xml","vaultcmd","NTDS.dit","SAM","SECURITY","web.config",".aws\\\\credentials",".azure"]);',
        'DeviceFileEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where FileName has_any (targets) or FolderPath has_any (targets)',
        ctx.where('DeviceName', 'has'),
        '| where not(InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","explorer.exe","MsMpEng.exe","SenseIR.exe","backup.exe"))',
        '| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-logon-failures-on-device',
      t: 'Failed logons per device',
      p: ['Endpoint', 'Credential access'],
      d: 'Bursts of failed logons on a device with the accounts tried, which separates a typo from a spray.',
      k: 'devicelogonevents logonfailed failurereason brute force spray local account attempts burst',
      days: 7, ent: DEVICE,
      vars: [['min', 'Minimum failures per hour', '20']],
      q: ctx => [
        'DeviceLogonEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where ActionType == "LogonFailed"',
        ctx.where('DeviceName', 'has'),
        '| summarize Failures = count(), Accounts = dcount(AccountName), AccountList = make_set(AccountName, 20),',
        '    Sources = make_set(RemoteIP, 10), Reasons = make_set(FailureReason, 5) by DeviceName, LogonType, bin(Timestamp, 1h)',
        '| where Failures >= ' + ctx.n('min', 20),
        '| sort by Failures desc'
      ]
    },
    {
      id: 'kql-success-after-failures',
      t: 'Successful logon after many failures',
      p: ['Endpoint', 'Credential access'],
      d: 'The moment a brute force works: a burst of failures for an account followed by a success from the same address.',
      k: 'brute force success after failure guessed password correlation logon burst then success compromise',
      days: 7,
      vars: [['min', 'Minimum failures before the success', '10']],
      q: ctx => [
        'let failures = DeviceLogonEvents',
        '    | where Timestamp > ' + ctx.ago,
        '    | where ActionType == "LogonFailed"',
        '    | summarize Failures = count(), FirstFail = min(Timestamp), LastFail = max(Timestamp) by AccountName, DeviceName, RemoteIP',
        '    | where Failures >= ' + ctx.n('min', 10) + ';',
        'DeviceLogonEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where ActionType == "LogonSuccess"',
        '| join kind=inner failures on AccountName, DeviceName, RemoteIP',
        '| where Timestamp between (FirstFail .. (LastFail + 30m))',
        '| project SuccessTime = Timestamp, AccountName, DeviceName, RemoteIP, LogonType, Failures, FirstFail, LastFail',
        '| sort by SuccessTime desc'
      ]
    },
    {
      id: 'kql-ldap-recon',
      t: 'LDAP reconnaissance against the domain',
      p: ['Identity', 'Discovery'],
      d: 'LDAP queries seen by Defender for Identity, with the filters that map to BloodHound style enumeration.',
      k: 'identityqueryevents ldap query enumeration bloodhound sharphound adfind domain recon serviceprincipalname',
      days: 7, ent: USER,
      opts: [['spn', 'Only queries that look for service accounts or admins', true]],
      req: 'Microsoft Defender for Identity sensors on the domain controllers.',
      q: ctx => [
        'IdentityQueryEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where ActionType has "LDAP"',
        ctx.where('AccountUpn'),
        ctx.on('spn') ? '| where Query has_any ("servicePrincipalName", "adminCount", "Domain Admins", "Enterprise Admins", "objectClass=user", "trustedForDelegation", "userAccountControl")' : null,
        '| summarize Queries = count(), Samples = make_set(Query, 5), Targets = make_set(QueryTarget, 5)',
        '    by AccountName, AccountDomain, DeviceName, IPAddress, bin(Timestamp, 1h)',
        '| sort by Queries desc'
      ]
    },
    {
      id: 'kql-samr-enumeration',
      t: 'SAMR and account enumeration',
      p: ['Identity', 'Discovery'],
      d: 'SAMR queries that enumerate users and groups, a step BloodHound and net commands both trigger.',
      k: 'samr enumeration net user domain group members identityqueryevents recon session enumeration',
      days: 7, ent: USER,
      req: 'Microsoft Defender for Identity sensors on the domain controllers.',
      q: ctx => [
        'IdentityQueryEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where ActionType has_any ("SAMR", "DNS", "SMB")',
        ctx.where('AccountUpn'),
        '| summarize Queries = count(), Types = make_set(ActionType, 5), Targets = make_set(QueryTarget, 10)',
        '    by AccountName, AccountDomain, DeviceName, IPAddress',
        '| sort by Queries desc'
      ]
    },
    {
      id: 'kql-dcsync-and-replication',
      t: 'DCSync and directory replication',
      p: ['Identity', 'Credential access'],
      d: 'Replication requests from something that is not a domain controller, which is how credentials get pulled straight from AD.',
      k: 'dcsync directory services replication getchanges drsuapi mimikatz lsadump identitydirectoryevents t1003.006',
      days: 30,
      req: 'Microsoft Defender for Identity sensors on the domain controllers.',
      q: ctx => [
        'IdentityDirectoryEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where ActionType has_any ("replication", "Directory Services")',
        '| project Timestamp, ActionType, AccountName, AccountDomain, AccountUpn, DeviceName, IPAddress, DestinationDeviceName, AdditionalFields',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-kerberos-weak-encryption',
      t: 'Kerberos tickets with weak encryption',
      p: ['Identity', 'Credential access'],
      d: 'RC4 and DES ticket requests, which is what kerberoasting and encryption downgrade attacks look for.',
      k: 'kerberos rc4 downgrade kerberoasting encryption type identitylogonevents ticket weak etype t1558.003',
      days: 14, ent: USER,
      req: 'Microsoft Defender for Identity sensors on the domain controllers.',
      q: ctx => [
        'IdentityLogonEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where Protocol has "Kerberos"',
        ctx.where('AccountUpn'),
        '| extend Details = tostring(AdditionalFields)',
        '| where Details has_any ("RC4", "DES", "rc4_hmac", "des-cbc")',
        '| summarize Requests = count(), Devices = make_set(DeviceName, 10), Targets = make_set(TargetDeviceName, 10)',
        '    by AccountName, AccountDomain, bin(Timestamp, 1h)',
        '| sort by Requests desc'
      ]
    },
    {
      id: 'kql-onprem-password-spray',
      t: 'On-premises password spray',
      p: ['Identity', 'Credential access'],
      d: 'One source failing against many domain accounts, seen from the domain controllers rather than from the endpoints.',
      k: 'identitylogonevents logonfailed spray many accounts one source domain controller ntlm kerberos preauth',
      days: 7,
      vars: [['min', 'Minimum distinct accounts', '10']],
      req: 'Microsoft Defender for Identity sensors on the domain controllers.',
      q: ctx => [
        'IdentityLogonEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where ActionType == "LogonFailed"',
        '| summarize Failures = count(), Accounts = dcount(AccountName), Targets = make_set(AccountName, 25),',
        '    Protocols = make_set(Protocol, 5), Reasons = make_set(FailureReason, 5) by DeviceName, IPAddress, bin(Timestamp, 1h)',
        '| where Accounts >= ' + ctx.n('min', 10),
        '| sort by Accounts desc'
      ]
    },
    {
      id: 'kql-ad-group-changes',
      t: 'Active Directory group membership changes',
      p: ['Identity', 'Privilege escalation'],
      d: 'Group changes seen by Defender for Identity, filtered to the groups that actually grant power.',
      k: 'identitydirectoryevents group membership changed domain admins privileged group added ad escalation',
      days: 30, ent: USER,
      opts: [['privileged', 'Only privileged groups', true]],
      req: 'Microsoft Defender for Identity sensors on the domain controllers.',
      q: ctx => [
        'IdentityDirectoryEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where ActionType has "Group Membership changed"',
        ctx.where('AccountUpn'),
        '| extend Details = tostring(AdditionalFields)',
        ctx.on('privileged') ? '| where Details has_any ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators", "Backup Operators", "DnsAdmins", "Server Operators")' : null,
        '| project Timestamp, ActionType, Actor = AccountName, Target = TargetAccountUpn, DeviceName, IPAddress, Details',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-privileged-account-on-workstation',
      t: 'Privileged accounts signing in to workstations',
      p: ['Identity', 'Privilege escalation'],
      d: 'Joins the identity inventory with device logons to catch tier zero accounts appearing on ordinary desktops.',
      k: 'identityinfo assignedroles global administrator logon workstation tiering credential exposure privileged access',
      days: 7,
      q: ctx => [
        'let privileged = IdentityInfo',
        '    | where isnotempty(AssignedRoles) and AssignedRoles != "[]"',
        '    | summarize Roles = any(AssignedRoles) by AccountUpn, AccountName;',
        'DeviceLogonEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where ActionType == "LogonSuccess" and LogonType in ("Interactive", "RemoteInteractive")',
        '| join kind=inner privileged on AccountName',
        '| join kind=leftouter (DeviceInfo | where Timestamp > ' + ctx.ago + ' | distinct DeviceName, DeviceType, OSPlatform) on DeviceName',
        '| where DeviceType != "Server"',
        '| project Timestamp, AccountName, AccountUpn, Roles, DeviceName, DeviceType, OSPlatform, LogonType, RemoteIP',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-dormant-account-active',
      t: 'Dormant accounts that woke up',
      p: ['Identity', 'Persistence'],
      d: 'Accounts with no activity for weeks that suddenly signed in, a favourite for attackers reusing forgotten credentials.',
      k: 'dormant stale account reactivated first activity after long gap unused sign-in anomaly forgotten',
      days: 30,
      vars: [['quiet', 'Quiet period in days', '21']],
      q: ctx => [
        'let quiet = ' + ctx.n('quiet', 21) + 'd;',
        'let lookback = ' + ctx.days + 'd;',
        'EntraIdSignInEvents',
        '| where Timestamp > ago(lookback)',
        '| where ErrorCode == 0',
        '| summarize FirstRecent = min(Timestamp), LastRecent = max(Timestamp), SignIns = count(),',
        '    Countries = make_set(Country, 5), IPs = make_set(IPAddress, 5) by AccountUpn',
        '| join kind=inner (',
        '    EntraIdSignInEvents',
        '    | where Timestamp between (ago(lookback) .. ago(quiet))',
        '    | summarize OlderSignIns = count() by AccountUpn',
        ') on AccountUpn',
        '| where FirstRecent > ago(quiet) and OlderSignIns == 0',
        '| sort by FirstRecent desc'
      ]
    }
  );

  /* -------------------------- cloud identity, OAuth applications and email */

  add(
    {
      id: 'kql-entra-new-country',
      t: 'First sign-in from a new country',
      p: ['Entra ID', 'Identity'],
      d: 'Compares the last few days against a longer baseline and keeps the country and account combinations that never appeared before.',
      k: 'new country baseline anomaly first time geography entraidsigninevents unfamiliar location travel',
      days: 30,
      vars: [['recent', 'Treat as new within (days)', '2']],
      q: ctx => [
        'let recent = ' + ctx.n('recent', 2) + 'd;',
        'let lookback = ' + ctx.days + 'd;',
        'let baseline = EntraIdSignInEvents',
        '    | where Timestamp between (ago(lookback) .. ago(recent))',
        '    | where ErrorCode == 0',
        '    | distinct AccountUpn, Country;',
        'EntraIdSignInEvents',
        '| where Timestamp > ago(recent)',
        '| where ErrorCode == 0 and isnotempty(Country)',
        '| join kind=leftanti baseline on AccountUpn, Country',
        '| summarize SignIns = count(), Apps = make_set(Application, 5), IPs = make_set(IPAddress, 5),',
        '    FirstSeen = min(Timestamp) by AccountUpn, Country, City',
        '| sort by FirstSeen desc'
      ]
    },
    {
      id: 'kql-entra-conditional-access-gaps',
      t: 'Successful sign-ins without conditional access',
      p: ['Entra ID', 'Identity'],
      d: 'Sign-ins that succeeded while no conditional access policy applied, which is where the gaps in coverage show up.',
      k: 'conditionalaccessstatus not applied single factor authenticationrequirement gap coverage policy bypass',
      days: 7, ent: USER,
      opts: [['singleFactor', 'Only sign-ins without multifactor', true], ['external', 'Only from outside your countries', false]],
      vars: [['home', 'Expected countries', 'BE,NL', 'text']],
      q: ctx => [
        'let expected = dynamic(["' + (ctx.v('home') || 'BE').split(',').map(s => s.trim()).join('","') + '"]);',
        'EntraIdSignInEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where ErrorCode == 0',
        ctx.where('AccountUpn'),
        '| where ConditionalAccessStatus == 2',
        ctx.on('singleFactor') ? '| where AuthenticationRequirement == "singleFactorAuthentication"' : null,
        ctx.on('external') ? '| where isnotempty(Country) and not(Country in (expected))' : null,
        '| summarize SignIns = count(), Apps = make_set(Application, 5), IPs = make_set(IPAddress, 5),',
        '    Countries = make_set(Country, 5), Clients = make_set(ClientAppUsed, 5) by AccountUpn',
        '| sort by SignIns desc'
      ]
    },
    {
      id: 'kql-entra-risky-successful',
      t: 'Risky sign-ins that still succeeded',
      p: ['Entra ID', 'Identity'],
      d: 'Identity Protection flagged the sign-in as risky and it went through anyway, which is the queue worth working first.',
      k: 'risklevelduringsignin riskstate identity protection risky sign-in succeeded medium high triage p2',
      days: 14, ent: USER,
      vars: [['risk', 'Minimum risk level (10 low, 50 medium, 100 high)', '50']],
      q: ctx => [
        'EntraIdSignInEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where ErrorCode == 0',
        '| where RiskLevelDuringSignIn >= ' + ctx.n('risk', 50),
        ctx.where('AccountUpn'),
        '| project Timestamp, AccountUpn, Application, ResourceDisplayName, IPAddress, Country, City,',
        '    RiskLevelDuringSignIn, RiskState, RiskEventTypes, ConditionalAccessStatus, ClientAppUsed, UserAgent',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-entra-guest-activity',
      t: 'Guest and external account activity',
      p: ['Entra ID', 'Identity'],
      d: 'What the guests in your tenant actually reach, which is usually broader than anyone expects.',
      k: 'isguestuser isexternaluser b2b guest external collaboration resource access sign-in scope',
      days: 14, ent: USER,
      view: [['summary', 'Count per guest and resource'], ['detail', 'Every sign-in']],
      q: ctx => [
        'EntraIdSignInEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where IsGuestUser == true or IsExternalUser == 1',
        ctx.where('AccountUpn'),
        ctx.view === 'detail'
          ? '| project Timestamp, AccountUpn, Application, ResourceDisplayName, IPAddress, Country, ErrorCode, ConditionalAccessStatus\n| sort by Timestamp desc'
          : '| summarize SignIns = count(), Resources = make_set(ResourceDisplayName, 10), Countries = make_set(Country, 5),\n    LastSeen = max(Timestamp) by AccountUpn\n| sort by SignIns desc'
      ]
    },
    {
      id: 'kql-entra-client-fingerprint',
      t: 'Unusual TLS fingerprints per account',
      p: ['Entra ID', 'Identity'],
      d: 'Uses the JA4 gateway fingerprint to spot a session replayed by a different client than the user normally uses.',
      k: 'gatewayja4 ja4 fingerprint tls client token replay aitm stolen cookie unusual client anomaly',
      days: 14, ent: USER,
      vars: [['max', 'Report accounts with more than (fingerprints)', '3']],
      q: ctx => [
        'EntraIdSignInEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where ErrorCode == 0 and isnotempty(GatewayJA4)',
        ctx.where('AccountUpn'),
        '| summarize Fingerprints = dcount(GatewayJA4), Clients = make_set(GatewayJA4, 10), Agents = make_set(UserAgent, 5),',
        '    IPs = dcount(IPAddress), Countries = make_set(Country, 5) by AccountUpn',
        '| where Fingerprints > ' + ctx.n('max', 3),
        '| sort by Fingerprints desc'
      ]
    },
    {
      id: 'kql-entra-spn-signins',
      t: 'Service principal sign-ins from new sources',
      p: ['Entra ID', 'Applications'],
      d: 'Workload identities signing in from an address or country they never used before, which is what a stolen secret looks like.',
      k: 'entraidspnsignin service principal workload identity secret stolen new ip country app-only daemon',
      days: 14,
      vars: [['recent', 'Treat as new within (days)', '2']],
      q: ctx => [
        'let recent = ' + ctx.n('recent', 2) + 'd;',
        'let lookback = ' + ctx.days + 'd;',
        'let baseline = EntraIdSpnSignInEvents',
        '    | where Timestamp between (ago(lookback) .. ago(recent))',
        '    | where ErrorCode == 0',
        '    | distinct ServicePrincipalName, IPAddress;',
        'EntraIdSpnSignInEvents',
        '| where Timestamp > ago(recent)',
        '| where ErrorCode == 0',
        '| join kind=leftanti baseline on ServicePrincipalName, IPAddress',
        '| summarize SignIns = count(), Resources = make_set(ResourceDisplayName, 5), FirstSeen = min(Timestamp)',
        '    by ServicePrincipalName, ServicePrincipalId, IPAddress, Country',
        '| sort by FirstSeen desc'
      ]
    },
    {
      id: 'kql-graph-api-activity',
      t: 'Microsoft Graph API calls',
      p: ['Entra ID', 'Applications', 'Exfiltration'],
      d: 'Who and what is calling Graph, with the request path, so bulk directory or mail reads through the API become visible.',
      k: 'graphapiauditevents requesturi requestmethod scopes serviceprincipalid api abuse bulk read directory graph',
      days: 7,
      opts: [['sensitive', 'Only sensitive resource paths', true], ['apps', 'Only application (app-only) calls', false]],
      view: [['summary', 'Count per caller and path'], ['detail', 'Every request']],
      q: ctx => [
        'GraphAPIAuditEvents',
        '| where Timestamp > ' + ctx.ago,
        ctx.on('sensitive') ? '| where RequestUri has_any ("/users", "/groups", "/messages", "/mailFolders", "/drive", "/directoryRoles", "/servicePrincipals", "/applications", "/policies")' : null,
        ctx.on('apps') ? '| where isnotempty(ServicePrincipalId)' : null,
        '| extend Path = tostring(split(tostring(parse_url(RequestUri).Path), "?")[0])',
        ctx.view === 'detail'
          ? '| project Timestamp, AccountObjectId, ServicePrincipalId, ApplicationId, RequestMethod, Path, ResponseStatusCode, IpAddress, Scopes\n| sort by Timestamp desc'
          : '| summarize Calls = count(), Methods = make_set(RequestMethod, 5), Statuses = make_set(ResponseStatusCode, 5),\n    LastSeen = max(Timestamp) by ApplicationId, ServicePrincipalId, AccountObjectId, Path\n| sort by Calls desc'
      ]
    },
    {
      id: 'kql-graph-api-bulk-read',
      t: 'Bulk directory reads through Graph',
      p: ['Entra ID', 'Exfiltration'],
      d: 'A single caller pulling an unusual volume of user, group or mail objects from Graph in a short window.',
      k: 'graph api bulk enumeration directory dump users groups messages volume anomaly scraping exfiltration',
      days: 7,
      vars: [['min', 'Minimum calls per hour', '200']],
      q: ctx => [
        'GraphAPIAuditEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where RequestMethod == "GET"',
        '| where RequestUri has_any ("/users", "/groups", "/messages", "/contacts", "/drive")',
        '| summarize Calls = count(), Paths = dcount(RequestUri), Sample = any(RequestUri), Bytes = sum(ResponseSize)',
        '    by ApplicationId, ServicePrincipalId, AccountObjectId, IpAddress, bin(Timestamp, 1h)',
        '| where Calls >= ' + ctx.n('min', 200),
        '| sort by Calls desc'
      ]
    },
    {
      id: 'kql-oauth-app-risk',
      t: 'Risky OAuth applications',
      p: ['Applications', 'Phishing'],
      d: 'App governance inventory sorted by risk, showing privilege level, publisher verification and how many users consented.',
      k: 'oauthappinfo app governance riskscore privilegelevel verifiedpublisher consentedusers permissions unverified',
      days: 7,
      req: 'App governance enabled in Microsoft Defender for Cloud Apps.',
      opts: [['unverified', 'Unverified publishers only', true], ['external', 'Apps registered in another tenant only', false]],
      vars: [['risk', 'Minimum risk score', '1']],
      q: ctx => [
        'OAuthAppInfo',
        '| where Timestamp > ' + ctx.ago,
        '| summarize arg_max(Timestamp, *) by OAuthAppId',
        '| where RiskScore >= ' + ctx.n('risk', 1),
        ctx.on('unverified') ? '| where isempty(tostring(VerifiedPublisher.DisplayName))' : null,
        ctx.on('external') ? '| where AppOrigin != "Internal"' : null,
        '| project AppName, OAuthAppId, AppStatus, PrivilegeLevel, RiskScore, IsAdminConsented, ConsentedUsersCount,',
        '    Publisher = tostring(VerifiedPublisher.DisplayName), AppOrigin, AddedOnTime, LastUsedTime',
        '| sort by RiskScore desc, ConsentedUsersCount desc'
      ]
    },
    {
      id: 'kql-oauth-app-mail-permissions',
      t: 'Applications that can read mail',
      p: ['Applications', 'Exfiltration'],
      d: 'Expands the permission array of every OAuth app and keeps the ones holding mail, file or directory write access.',
      k: 'permissions mail.read files.readwrite.all directory.readwrite mv-expand app governance scopes graph consent',
      days: 7,
      req: 'App governance enabled in Microsoft Defender for Cloud Apps.',
      q: ctx => [
        'OAuthAppInfo',
        '| where Timestamp > ' + ctx.ago,
        '| summarize arg_max(Timestamp, *) by OAuthAppId',
        '| mv-expand Permission = Permissions',
        '| extend PermissionName = tostring(Permission.PermissionName), PermissionType = tostring(Permission.PermissionType),',
        '    UsageStatus = tostring(Permission.UsageStatus)',
        '| where PermissionName has_any ("Mail.", "MailboxSettings.", "Files.", "Sites.", "Directory.ReadWrite", "Application.ReadWrite", "User.ReadWrite")',
        '| project AppName, OAuthAppId, PermissionName, PermissionType, UsageStatus, PrivilegeLevel, RiskScore,',
        '    IsAdminConsented, ConsentedUsersCount, LastUsedTime',
        '| sort by RiskScore desc, AppName asc'
      ]
    },
    {
      id: 'kql-app-role-assignments',
      t: 'Application permissions granted',
      p: ['Applications', 'Privilege escalation'],
      d: 'Audit records where an app role was assigned to a service principal, which is how an app gains tenant wide access.',
      k: 'add app role assignment to service principal approleassignment application permission granted cloudappevents',
      days: 30,
      q: ctx => [
        'CloudAppEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where ActionType in ("Add app role assignment to service principal.", "Add app role assignment grant to user.",',
        '    "Add delegated permission grant.", "Consent to application.")',
        '| extend Details = tostring(RawEventData.ModifiedProperties)',
        '| extend Target = tostring(RawEventData.Target)',
        '| project Timestamp, AccountDisplayName, ActionType, Target, Details, IPAddress, UserAgent, IsAdminOperation',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-cloud-admin-activity',
      t: 'Administrative actions in cloud apps',
      p: ['Cloud apps', 'Privilege escalation'],
      d: 'Every action flagged as an admin operation, grouped by actor and address so an unfamiliar admin source stands out.',
      k: 'isadminoperation cloudappevents admin activity portal powershell unusual location privileged action',
      days: 7, ent: USER,
      view: [['summary', 'Count per actor and IP'], ['detail', 'Every action']],
      q: ctx => [
        'CloudAppEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where IsAdminOperation == true',
        ctx.ent ? '| where AccountDisplayName has "' + ctx.ent + '"' : null,
        ctx.view === 'detail'
          ? '| project Timestamp, AccountDisplayName, Application, ActionType, ObjectName, IPAddress, CountryCode, UserAgent\n| sort by Timestamp desc'
          : '| summarize Actions = count(), Types = make_set(ActionType, 10), Apps = make_set(Application, 5),\n    LastSeen = max(Timestamp) by AccountDisplayName, IPAddress, CountryCode\n| sort by Actions desc'
      ]
    },
    {
      id: 'kql-cloud-anonymous-ip',
      t: 'Cloud activity from anonymous proxies',
      p: ['Cloud apps', 'Identity'],
      d: 'Actions coming through Tor or a commercial proxy, using the address tags Defender for Cloud Apps already assigns.',
      k: 'isanonymousproxy iptags iscategory tor proxy vpn anonymised cloudappevents risky ip address tag',
      days: 14, ent: USER,
      q: ctx => [
        'CloudAppEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where IsAnonymousProxy == true or tostring(IPTags) has_any ("Anonymous proxy", "Tor", "Malicious", "Botnet")',
        ctx.ent ? '| where AccountDisplayName has "' + ctx.ent + '"' : null,
        '| project Timestamp, AccountDisplayName, Application, ActionType, ObjectName, IPAddress, IPTags, CountryCode, City, UserAgent',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-cloud-impossible-travel',
      t: 'Cloud app activity from two countries',
      p: ['Cloud apps', 'Identity'],
      d: 'Accounts acting from more than one country inside a short window, based on cloud app activity rather than sign-ins.',
      k: 'cloudappevents countrycode impossible travel two countries window session hijack concurrent access',
      days: 7,
      vars: [['window', 'Window in hours', '4']],
      q: ctx => [
        'CloudAppEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where isnotempty(CountryCode)',
        '| summarize Countries = make_set(CountryCode), CountryCount = dcount(CountryCode), IPs = make_set(IPAddress, 10),',
        '    Actions = count() by AccountDisplayName, bin(Timestamp, ' + ctx.n('window', 4) + 'h)',
        '| where CountryCount > 1',
        '| sort by CountryCount desc, Timestamp desc'
      ]
    },
    {
      id: 'kql-phish-delivered-to-inbox',
      t: 'Phishing that reached the inbox',
      p: ['Email', 'Phishing'],
      d: 'Mail classified as phish or malware that was still delivered, the queue that needs remediation rather than review.',
      k: 'emailevents deliveryaction delivered threattypes phish malware inbox latestdeliverylocation remediation zap',
      days: 7,
      opts: [['inboxOnly', 'Only mail still in the inbox', true]],
      view: [['detail', 'Every message'], ['summary', 'Count per sender domain']],
      q: ctx => [
        'EmailEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where ThreatTypes has_any ("Phish", "Malware")',
        '| where DeliveryAction == "Delivered"',
        ctx.on('inboxOnly') ? '| where LatestDeliveryLocation == "Inbox/folder"' : null,
        ctx.view === 'summary'
          ? '| summarize Messages = count(), Recipients = dcount(RecipientEmailAddress), Subjects = make_set(Subject, 5)\n    by SenderFromDomain, ThreatTypes\n| sort by Messages desc'
          : '| project Timestamp, SenderFromAddress, SenderIPv4, RecipientEmailAddress, Subject, ThreatTypes, DetectionMethods,\n    DeliveryAction, LatestDeliveryLocation, NetworkMessageId\n| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-email-post-delivery',
      t: 'Post delivery removals and ZAP',
      p: ['Email', 'Phishing'],
      d: 'What zero hour auto purge and manual remediation pulled back after delivery, including the actions that failed.',
      k: 'emailpostdeliveryevents zap phish malware manual remediation actionresult removed after delivery',
      days: 7,
      q: ctx => [
        'EmailPostDeliveryEvents',
        '| where Timestamp > ' + ctx.ago,
        '| join kind=leftouter (EmailEvents | where Timestamp > ' + ctx.ago + ' | project NetworkMessageId, Subject, SenderFromAddress, ThreatTypes) on NetworkMessageId',
        '| project Timestamp, Action, ActionType, ActionResult, ActionTrigger, RecipientEmailAddress, SenderFromAddress, Subject, ThreatTypes, DeliveryLocation',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-email-attachment-on-endpoint',
      t: 'Mail attachments that ran on a device',
      p: ['Email', 'Endpoint', 'Phishing'],
      d: 'Joins attachment hashes to endpoint file and process events, which proves whether a phishing payload actually executed.',
      k: 'emailattachmentinfo sha256 join deviceprocessevents devicefileevents payload executed detonation correlation',
      days: 14,
      opts: [['executed', 'Only attachments that were executed', false]],
      q: ctx => [
        'let attachments = EmailAttachmentInfo',
        '    | where Timestamp > ' + ctx.ago,
        '    | where isnotempty(SHA256)',
        '    | project EmailTime = Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, FileName, SHA256, ThreatTypes;',
        ctx.on('executed')
          ? 'DeviceProcessEvents\n| where Timestamp > ' + ctx.ago + '\n| join kind=inner attachments on SHA256\n| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SenderFromAddress, RecipientEmailAddress, ThreatTypes, EmailTime'
          : 'DeviceFileEvents\n| where Timestamp > ' + ctx.ago + '\n| join kind=inner attachments on SHA256\n| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, SenderFromAddress, RecipientEmailAddress, ThreatTypes, EmailTime',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-lookalike-sender-domains',
      t: 'Lookalike sender domains',
      p: ['Email', 'Phishing'],
      d: 'External senders whose domain closely resembles your own, which is the mechanic behind most invoice fraud.',
      k: 'lookalike typosquat cousin domain similar sender impersonation display name spoof brand homoglyph',
      days: 14,
      vars: [['domain', 'Your domain', 'contoso.com', 'text']],
      q: ctx => [
        'let ourDomain = "' + (ctx.v('domain') || 'contoso.com') + '";',
        'let brand = tostring(split(ourDomain, ".")[0]);',
        'EmailEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where EmailDirection == "Inbound"',
        '| where isnotempty(SenderFromDomain) and SenderFromDomain != ourDomain',
        '// Fold the usual homoglyph swaps so contos0.com and cont0so.com still match the brand.',
        '| extend Folded = tolower(SenderFromDomain)',
        '| extend Folded = replace_string(Folded, "0", "o")',
        '| extend Folded = replace_string(Folded, "1", "l")',
        '| extend Folded = replace_string(Folded, "rn", "m")',
        '| extend Folded = replace_string(Folded, "-", "")',
        '| where Folded has brand',
        '| summarize Messages = count(), Recipients = dcount(RecipientEmailAddress), Subjects = make_set(Subject, 5),',
        '    Actions = make_set(DeliveryAction, 3) by SenderFromDomain, Folded',
        '| sort by Messages desc'
      ]
    },
    {
      id: 'kql-email-authentication-failures',
      t: 'Senders failing SPF, DKIM and DMARC',
      p: ['Email', 'Phishing'],
      d: 'Inbound mail that failed authentication but was still delivered, ranked by how much of it landed.',
      k: 'authenticationdetails spf dkim dmarc compauth fail delivered spoofing header authentication inbound',
      days: 7,
      opts: [['deliveredOnly', 'Only mail that was delivered', true]],
      q: ctx => [
        'EmailEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where EmailDirection == "Inbound"',
        ctx.on('deliveredOnly') ? '| where DeliveryAction == "Delivered"' : null,
        '| extend Auth = parse_json(AuthenticationDetails)',
        '| extend SPF = tostring(Auth.SPF), DKIM = tostring(Auth.DKIM), DMARC = tostring(Auth.DMARC), CompAuth = tostring(Auth.CompAuth)',
        '| where SPF == "fail" or DKIM == "fail" or DMARC == "fail" or CompAuth == "fail"',
        '| summarize Messages = count(), Recipients = dcount(RecipientEmailAddress), Subjects = make_set(Subject, 3),',
        '    Results = make_set(strcat("spf:", SPF, " dkim:", DKIM, " dmarc:", DMARC), 3) by SenderFromDomain, SenderIPv4',
        '| sort by Messages desc'
      ]
    },
    {
      id: 'kql-email-password-protected-archives',
      t: 'Password protected archives by mail',
      p: ['Email', 'Phishing'],
      d: 'Archive attachments that scanners cannot open, a delivery trick that still works far too often.',
      k: 'emailattachmentinfo zip rar 7z iso img encrypted password protected archive scanner evasion malware',
      days: 14,
      q: ctx => [
        'EmailAttachmentInfo',
        '| where Timestamp > ' + ctx.ago,
        '| where FileType in~ ("zip", "rar", "7z", "iso", "img", "cab", "ace", "gz") or FileName has_any (".zip", ".rar", ".7z", ".iso", ".img")',
        '| join kind=leftouter (EmailEvents | where Timestamp > ' + ctx.ago + ' | project NetworkMessageId, Subject, DeliveryAction, EmailDirection, SenderFromDomain) on NetworkMessageId',
        '| where EmailDirection == "Inbound"',
        '| project Timestamp, SenderFromAddress, SenderFromDomain, RecipientEmailAddress, Subject, FileName, FileType, FileSize, ThreatTypes, DeliveryAction',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-outbound-mail-burst',
      t: 'Internal account sending a burst of mail',
      p: ['Email', 'Phishing'],
      d: 'Outbound volume spikes from one sender, the first visible effect of a mailbox being used to spread phishing.',
      k: 'outbound emaildirection volume spike burst internal sender compromised mailbox spam wave recipients',
      days: 7,
      vars: [['min', 'Minimum recipients per hour', '50']],
      q: ctx => [
        'EmailEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where EmailDirection in ("Outbound", "Intra-org")',
        '| summarize Messages = count(), Recipients = dcount(RecipientEmailAddress), Subjects = make_set(Subject, 5),',
        '    Threats = make_set(ThreatTypes, 3) by SenderFromAddress, bin(Timestamp, 1h)',
        '| where Recipients >= ' + ctx.n('min', 50),
        '| sort by Recipients desc'
      ]
    },
    {
      id: 'kql-email-campaign-view',
      t: 'Phishing campaigns in the tenant',
      p: ['Email', 'Phishing'],
      d: 'The campaign view from Defender for Office, which groups related messages so you can scope a wave in one row.',
      k: 'campaigninfo campaign phishing wave cluster impact delivered blocked scope threat',
      days: 30,
      req: 'Microsoft Defender for Office 365 Plan 2.',
      q: ctx => [
        'CampaignInfo',
        '| where Timestamp > ' + ctx.ago,
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-teams-phishing',
      t: 'Suspicious Teams messages and links',
      p: ['Teams', 'Phishing'],
      d: 'Teams messages carrying URLs, especially from external senders, now that chat is a normal delivery channel.',
      k: 'messageevents messageurlinfo teams chat phishing external sender link delivery messagepostdeliveryevents',
      days: 7,
      opts: [['external', 'External senders only', true]],
      q: ctx => [
        'let urls = MessageUrlInfo',
        '    | where Timestamp > ' + ctx.ago,
        '    | project TeamsMessageId, Url, UrlDomain;',
        'MessageEvents',
        '| where Timestamp > ' + ctx.ago,
        ctx.on('external') ? '| where IsExternalThread == true' : null,
        '| join kind=inner urls on TeamsMessageId',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-malicious-files-in-sharepoint',
      t: 'Malicious files in SharePoint and Teams',
      p: ['SharePoint', 'Phishing'],
      d: 'Files that Defender for Office flagged inside SharePoint, OneDrive or Teams, with where they live.',
      k: 'filemaliciouscontentinfo sharepoint onedrive teams malware detected file threat safe attachments',
      days: 14,
      req: 'Microsoft Defender for Office 365 with Safe Attachments for SharePoint, OneDrive and Teams.',
      q: ctx => [
        'FileMaliciousContentInfo',
        '| where Timestamp > ' + ctx.ago,
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-url-clicks-allowed',
      t: 'Safe Links clicks that went through',
      p: ['Email', 'Phishing'],
      d: 'Clicks that were allowed or clicked through a warning, across mail, Teams and Office apps.',
      k: 'urlclickevents clickallowed isclickedthrough safe links warning bypass workload teams office click',
      days: 7, ent: USER,
      opts: [['through', 'Only clicks that bypassed a warning', false]],
      q: ctx => [
        'UrlClickEvents',
        '| where Timestamp > ' + ctx.ago,
        ctx.where('AccountUpn'),
        ctx.on('through') ? '| where IsClickedThrough != "0"' : '| where ActionType in ("ClickAllowed", "UrlErrorPage", "ClickAllowedByTenantPolicy") or IsClickedThrough != "0"',
        '| project Timestamp, AccountUpn, Workload, ActionType, IsClickedThrough, Url, ThreatTypes, DetectionMethods, IPAddress, NetworkMessageId',
        '| sort by Timestamp desc'
      ]
    }
  );

  /* ------------- cloud infrastructure, exposure, posture and triage tooling */

  add(
    {
      id: 'kql-cloud-role-assignments',
      t: 'Cloud role assignments and policy changes',
      p: ['Cloud infrastructure', 'Privilege escalation'],
      d: 'Control plane writes that grant access in Azure, AWS or GCP, which is how a foothold turns into ownership.',
      k: 'cloudauditevents roleassignments write iam attachuserpolicy setiampolicy azure aws gcp privilege escalation',
      days: 14,
      req: 'Microsoft Defender for Cloud connected to Defender XDR.',
      q: ctx => [
        'CloudAuditEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where OperationName has_any ("roleAssignments/write", "roleDefinitions/write", "AttachUserPolicy", "AttachRolePolicy",',
        '    "PutUserPolicy", "CreateRole", "SetIamPolicy", "AddIAMPolicyBinding", "elevateAccess")',
        '| project Timestamp, DataSource, ActionType, OperationName, ResourceId, IPAddress, CountryCode, UserAgent, AdditionalFields',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-cloud-secret-access',
      t: 'Key vault and secret store access',
      p: ['Cloud infrastructure', 'Credential access'],
      d: 'Reads and changes against secret stores, ranked per caller so a sudden bulk read is obvious.',
      k: 'keyvault secrets getsecret listsecrets secretsmanager getsecretvalue vault access credential access cloud',
      days: 14,
      req: 'Microsoft Defender for Cloud connected to Defender XDR.',
      vars: [['min', 'Minimum operations per hour', '10']],
      q: ctx => [
        'CloudAuditEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where OperationName has_any ("vaults/secrets", "vaults/keys", "GetSecretValue", "ListSecrets", "secretmanager", "vaults/certificates")',
        '| summarize Operations = count(), Names = make_set(OperationName, 5), Resources = make_set(ResourceId, 10),',
        '    Countries = make_set(CountryCode, 3) by DataSource, IPAddress, UserAgent, bin(Timestamp, 1h)',
        '| where Operations >= ' + ctx.n('min', 10),
        '| sort by Operations desc'
      ]
    },
    {
      id: 'kql-cloud-new-credentials',
      t: 'New cloud credentials created',
      p: ['Cloud infrastructure', 'Persistence'],
      d: 'Access keys, service account keys and application secrets minted on the control plane, a durable persistence trick.',
      k: 'createaccesskey createserviceaccountkey addkey credentials cloudauditevents persistence aws iam gcp key',
      days: 30,
      req: 'Microsoft Defender for Cloud connected to Defender XDR.',
      q: ctx => [
        'CloudAuditEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where OperationName has_any ("CreateAccessKey", "CreateLoginProfile", "CreateUser", "CreateServiceAccountKey",',
        '    "serviceAccounts.keys.create", "addKey", "regenerateKey", "listKeys")',
        '| project Timestamp, DataSource, ActionType, OperationName, ResourceId, IPAddress, CountryCode, Isp, UserAgent, AdditionalFields',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-cloud-destructive-operations',
      t: 'Destructive cloud operations',
      p: ['Cloud infrastructure', 'Ransomware'],
      d: 'Bursts of delete operations against cloud resources, which is what both ransomware and a bad script look like.',
      k: 'delete resources storage vm snapshot backup destruction cloudauditevents mass delete burst impact',
      days: 7,
      req: 'Microsoft Defender for Cloud connected to Defender XDR.',
      vars: [['min', 'Minimum deletes per hour', '10']],
      q: ctx => [
        'CloudAuditEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where ActionType == "Delete" or OperationName has_any ("/delete", "DeleteBucket", "DeleteObject", "DeleteDBInstance", "DeleteSnapshot")',
        '| summarize Deletes = count(), Resources = make_set(ResourceId, 10), Operations = make_set(OperationName, 5)',
        '    by DataSource, IPAddress, UserAgent, bin(Timestamp, 1h)',
        '| where Deletes >= ' + ctx.n('min', 10),
        '| sort by Deletes desc'
      ]
    },
    {
      id: 'kql-cloud-control-plane-anonymous',
      t: 'Cloud control plane from anonymous addresses',
      p: ['Cloud infrastructure', 'Identity'],
      d: 'Management operations arriving through anonymous proxies or unexpected countries.',
      k: 'isanonymousproxy cloudauditevents control plane tor vpn country unexpected management operation',
      days: 14,
      req: 'Microsoft Defender for Cloud connected to Defender XDR.',
      vars: [['home', 'Expected countries', 'BE,NL', 'text']],
      q: ctx => [
        'let expected = dynamic(["' + (ctx.v('home') || 'BE').split(',').map(s => s.trim()).join('","') + '"]);',
        'CloudAuditEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where IsAnonymousProxy == true or (isnotempty(CountryCode) and not(CountryCode in (expected)))',
        '| project Timestamp, DataSource, OperationName, ResourceId, IPAddress, IsAnonymousProxy, CountryCode, City, Isp, UserAgent',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-container-shell-access',
      t: 'Shells started inside containers',
      p: ['Cloud infrastructure', 'Execution'],
      d: 'Interactive shells and package installs inside running containers, which is rarely part of a normal deployment.',
      k: 'cloudprocessevents container kubernetes exec shell bash sh curl apt install runtime workload defender containers',
      days: 7,
      req: 'Microsoft Defender for Containers connected to Defender XDR.',
      q: ctx => [
        'CloudProcessEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where ProcessCommandLine has_any ("/bin/sh", "/bin/bash", "kubectl exec", "apt-get install", "apk add", "curl ", "wget ", "nc ", "python -c")',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-cloud-mining-dns',
      t: 'Crypto mining lookups from cloud workloads',
      p: ['Cloud infrastructure', 'Network'],
      d: 'DNS queries from cloud resources to known mining pools, the cheapest signal that a workload is compromised.',
      k: 'clouddnsevents mining pool xmr monero minergate nanopool cryptonight coinhive cloud workload dns',
      days: 14,
      req: 'Microsoft Defender for Cloud with DNS telemetry.',
      q: ctx => [
        'let pools = dynamic(["pool.minexmr","nanopool","supportxmr","minergate","f2pool","xmrpool","cryptonight","nicehash",',
        '    "2miners","hashvault","moneroocean","zergpool","ethermine"]);',
        'CloudDnsEvents',
        '| where Timestamp > ' + ctx.ago,
        '| where QueryName has_any (pools)',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-exposure-internet-facing',
      t: 'Internet facing assets with critical exposure',
      p: ['Exposure', 'Vulnerabilities'],
      d: 'Nodes in the exposure graph that are reachable from the internet, joined with their criticality.',
      k: 'exposuregraphnodes internet facing exposed asset criticality attack surface exposure management external',
      days: 7,
      req: 'Microsoft Security Exposure Management.',
      q: ctx => [
        'ExposureGraphNodes',
        '| where set_has_element(Categories, "compute") or set_has_element(Categories, "identity") or isnotempty(NodeName)',
        '| extend Exposed = tostring(NodeProperties.rawData.exposedToInternet)',
        '| extend Criticality = tostring(NodeProperties.rawData.criticalityLevel.criticalityLevel)',
        '| where isnotempty(Exposed) and Exposed != "false"',
        '| project NodeName, NodeLabel, Categories, Exposed, Criticality, NodeId',
        '| sort by Criticality asc, NodeName asc'
      ]
    },
    {
      id: 'kql-exposure-attack-paths',
      t: 'Paths from exposed assets to crown jewels',
      p: ['Exposure', 'Privilege escalation'],
      d: 'Walks the exposure graph edges from an internet facing node to a critical asset, which is the shape of a real attack path.',
      k: 'exposuregraphedges attack path critical asset lateral relationship can authenticate as graph exposure management',
      days: 7,
      req: 'Microsoft Security Exposure Management.',
      q: ctx => [
        'let critical = ExposureGraphNodes',
        '    | extend Criticality = tostring(NodeProperties.rawData.criticalityLevel.criticalityLevel)',
        '    | where isnotempty(Criticality)',
        '    | project TargetNodeId = NodeId, TargetName = NodeName, Criticality;',
        'ExposureGraphEdges',
        '| where EdgeLabel in ("can authenticate as", "has permissions to", "can remote interactive logon to", "contains", "member of")',
        '| join kind=inner critical on TargetNodeId',
        '| project SourceNodeName, SourceNodeLabel, EdgeLabel, TargetName, TargetNodeLabel, Criticality',
        '| sort by Criticality asc'
      ]
    },
    {
      id: 'kql-vulnerable-exposed-devices',
      t: 'Exploitable vulnerabilities on exposed devices',
      p: ['Vulnerabilities', 'Exposure'],
      d: 'Joins the vulnerability list with the exploit knowledge base and keeps the internet facing machines first.',
      k: 'devicetvmsoftwarevulnerabilities isexploitavailable cvssscore critical internet facing patch priority cve',
      days: 7, ent: DEVICE,
      opts: [['exploit', 'Only vulnerabilities with a public exploit', true], ['facing', 'Only internet facing devices', true]],
      q: ctx => [
        'DeviceTvmSoftwareVulnerabilities',
        '| where VulnerabilitySeverityLevel in ("Critical", "High")',
        ctx.where('DeviceName', 'has'),
        '| join kind=inner (DeviceTvmSoftwareVulnerabilitiesKB | project CveId, CvssScore, IsExploitAvailable, PublishedDate, VulnerabilityDescription) on CveId',
        ctx.on('exploit') ? '| where IsExploitAvailable == 1' : null,
        ctx.on('facing')
          ? '| join kind=inner (DeviceInfo | where Timestamp > ' + ctx.ago + ' | where IsInternetFacing == true | distinct DeviceId, DeviceName) on DeviceId'
          : null,
        '| summarize Devices = dcount(DeviceId), DeviceList = make_set(DeviceName, 10), MaxCvss = max(CvssScore)',
        '    by CveId, SoftwareName, SoftwareVendor, VulnerabilitySeverityLevel, IsExploitAvailable',
        '| sort by MaxCvss desc, Devices desc'
      ]
    },
    {
      id: 'kql-end-of-support-software',
      t: 'Software past end of support',
      p: ['Vulnerabilities', 'Posture'],
      d: 'Products that no longer receive security updates, grouped so you can see the size of each problem.',
      k: 'devicetvmsoftwareinventory endofsupportstatus eol end of life unsupported software upgrade inventory',
      days: 7, ent: DEVICE,
      q: ctx => [
        'DeviceTvmSoftwareInventory',
        '| where EndOfSupportStatus in ("EOS Version", "Upcoming EOS Version", "EOS Software", "Upcoming EOS Software")',
        ctx.where('DeviceName', 'has'),
        '| summarize Devices = dcount(DeviceId), DeviceList = make_set(DeviceName, 10)',
        '    by SoftwareVendor, SoftwareName, SoftwareVersion, EndOfSupportStatus, EndOfSupportDate',
        '| sort by Devices desc'
      ]
    },
    {
      id: 'kql-secure-configuration-gaps',
      t: 'Devices failing security configurations',
      p: ['Vulnerabilities', 'Posture'],
      d: 'Configuration checks that fail across the estate, with the description and remediation from the knowledge base.',
      k: 'devicetvmsecureconfigurationassessment iscompliant configuration baseline hardening remediation gaps posture',
      days: 7, ent: DEVICE,
      opts: [['high', 'High impact configurations only', true]],
      q: ctx => [
        'DeviceTvmSecureConfigurationAssessment',
        '| where IsApplicable == 1 and IsCompliant == 0',
        ctx.where('DeviceName', 'has'),
        '| join kind=inner (DeviceTvmSecureConfigurationAssessmentKB | project ConfigurationId, ConfigurationName, ConfigurationCategory, ConfigurationImpact, RemediationOptions) on ConfigurationId',
        ctx.on('high') ? '| where ConfigurationImpact >= 7' : null,
        '| summarize Devices = dcount(DeviceId), DeviceList = make_set(DeviceName, 10)',
        '    by ConfigurationName, ConfigurationCategory, ConfigurationImpact',
        '| sort by Devices desc, ConfigurationImpact desc'
      ]
    },
    {
      id: 'kql-browser-extensions',
      t: 'Risky browser extensions',
      p: ['Vulnerabilities', 'Endpoint'],
      d: 'Installed browser extensions ranked by the risk rating from vulnerability management.',
      k: 'devicetvmbrowserextensions extension risk chrome edge permissions installed browser addon',
      days: 7, ent: DEVICE,
      req: 'Microsoft Defender Vulnerability Management (browser extensions is in preview).',
      q: ctx => [
        'DeviceTvmBrowserExtensions',
        ctx.where('DeviceName', 'has'),
        '| summarize Devices = dcount(DeviceId), DeviceList = make_set(DeviceName, 10) by BrowserName, ExtensionName, ExtensionId, ExtensionRisk',
        '| sort by ExtensionRisk desc, Devices desc'
      ]
    },
    {
      id: 'kql-sensor-health',
      t: 'Devices with an unhealthy sensor',
      p: ['Posture', 'Triage'],
      d: 'Machines that stopped reporting or were never fully onboarded, which are the blind spots in every hunt.',
      k: 'deviceinfo sensorhealthstate onboardingstatus inactive misconfigured no sensor data blind spot coverage',
      days: 7,
      q: ctx => [
        'DeviceInfo',
        '| where Timestamp > ' + ctx.ago,
        '| summarize arg_max(Timestamp, *) by DeviceId',
        '| where SensorHealthState != "Active" or OnboardingStatus != "Onboarded"',
        '| project DeviceName, DeviceType, OSPlatform, OSVersion, SensorHealthState, OnboardingStatus, LastSeen = Timestamp, MachineGroup',
        '| sort by LastSeen asc'
      ]
    },
    {
      id: 'kql-internet-facing-inventory',
      t: 'Internet facing device inventory',
      p: ['Posture', 'Exposure'],
      d: 'The machines Defender considers reachable from the internet, with their exposure level and public address.',
      k: 'deviceinfo isinternetfacing publicip exposurelevel assetvalue perimeter external attack surface inventory',
      days: 7,
      q: ctx => [
        'DeviceInfo',
        '| where Timestamp > ' + ctx.ago,
        '| summarize arg_max(Timestamp, *) by DeviceId',
        '| where IsInternetFacing == true',
        '| project DeviceName, DeviceType, OSPlatform, OSVersion, PublicIP, ExposureLevel, AssetValue, MachineGroup, LastSeen = Timestamp',
        '| sort by ExposureLevel asc, DeviceName asc'
      ]
    },
    {
      id: 'kql-data-security-events',
      t: 'Purview data security events',
      p: ['Insider risk', 'Exfiltration'],
      d: 'User activity that breached a data security policy, the insider risk feed inside advanced hunting.',
      k: 'datasecurityevents purview insider risk dlp policy violation activity exfiltration preview',
      days: 14,
      req: 'Microsoft Purview Insider Risk Management (this table is in preview).',
      q: ctx => [
        'DataSecurityEvents',
        '| where Timestamp > ' + ctx.ago,
        '| summarize Events = count(), Types = make_set(ActionType, 10), LastSeen = max(Timestamp) by ActionType',
        '| sort by Events desc'
      ]
    },
    {
      id: 'kql-data-security-behaviors',
      t: 'Suspicious data behaviours',
      p: ['Insider risk', 'Exfiltration'],
      d: 'The behaviour level view from Purview, which groups related data activity into something worth reviewing.',
      k: 'datasecuritybehaviors insider risk behaviour suspicious data movement purview preview review',
      days: 30,
      req: 'Microsoft Purview Insider Risk Management (this table is in preview).',
      q: ctx => [
        'DataSecurityBehaviors',
        '| where Timestamp > ' + ctx.ago,
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-departing-user-activity',
      t: 'File activity by a departing user',
      p: ['Insider risk', 'Exfiltration'],
      d: 'Combines cloud downloads, endpoint writes to removable media and archive creation for one account.',
      k: 'departing leaver resignation data theft download usb archive collection insider one user combined view',
      days: 30, ent: USER,
      q: ctx => [
        'let account = "' + (ctx.ent || 'jdoe@contoso.com') + '";',
        'union isfuzzy=true',
        '    (CloudAppEvents',
        '        | where Timestamp > ' + ctx.ago,
        '        | where AccountDisplayName =~ account or AccountId =~ account',
        '        | where ActionType has_any ("FileDownloaded", "FileSyncDownloadedFull", "AnonymousLinkCreated", "SharingSet", "FileUploaded")',
        '        | project Timestamp, Source = "Cloud", Action = ActionType, Details = tostring(ObjectName), Address = IPAddress),',
        '    (DeviceFileEvents',
        '        | where Timestamp > ' + ctx.ago,
        '        | where InitiatingProcessAccountUpn =~ account',
        '        | where FolderPath matches regex @"^[D-Z]:\\\\\\\\" or FileName has_any (".zip", ".rar", ".7z")',
        '        | project Timestamp, Source = "Endpoint", Action = ActionType, Details = strcat(FolderPath, FileName), Address = DeviceName),',
        '    (EmailEvents',
        '        | where Timestamp > ' + ctx.ago,
        '        | where SenderFromAddress =~ account and EmailDirection == "Outbound"',
        '        | project Timestamp, Source = "Email", Action = DeliveryAction, Details = strcat(RecipientEmailAddress, " : ", Subject), Address = SenderIPv4)',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-alerts-overview',
      t: 'Alert overview by product and severity',
      p: ['Triage'],
      d: 'A quick shape of the alert load: which products fire, at which severity, and which titles repeat.',
      k: 'alertinfo severity servicesource category title summarize triage volume noisy alerts overview soc',
      days: 7,
      view: [['bySeverity', 'Count per product and severity'], ['byTitle', 'Count per alert title'], ['detail', 'Every alert']],
      q: ctx => [
        'AlertInfo',
        '| where Timestamp > ' + ctx.ago,
        ctx.view === 'byTitle'
          ? '| summarize Alerts = count(), Severities = make_set(Severity, 4), Sources = make_set(ServiceSource, 5), LastSeen = max(Timestamp) by Title\n| sort by Alerts desc'
          : ctx.view === 'detail'
            ? '| project Timestamp, AlertId, Title, Severity, Category, ServiceSource, DetectionSource, AttackTechniques\n| sort by Timestamp desc'
            : '| summarize Alerts = count() by ServiceSource, Severity\n| sort by Alerts desc'
      ]
    },
    {
      id: 'kql-alert-evidence-for-entity',
      t: 'Alerts touching one entity',
      p: ['Triage'],
      d: 'Finds every alert connected to a device, account, file or address, which is the fastest way to scope an entity.',
      k: 'alertevidence entitytype account device file ip url sha256 pivot scope entity alerts correlation',
      days: 30, ent: ['Entity (device, account, IP, hash)', 'PC-001'],
      q: ctx => [
        'AlertEvidence',
        '| where Timestamp > ' + ctx.ago,
        ctx.ent
          ? '| where DeviceName has "' + ctx.ent + '" or AccountUpn has "' + ctx.ent + '" or RemoteIP == "' + ctx.ent + '"\n    or SHA256 == "' + ctx.ent + '" or FileName has "' + ctx.ent + '" or AccountName has "' + ctx.ent + '"'
          : null,
        '| join kind=inner (AlertInfo | where Timestamp > ' + ctx.ago + ' | project AlertId, Title, Severity, Category, ServiceSource, AttackTechniques) on AlertId',
        '| project Timestamp, AlertId, Title, Severity, Category, ServiceSource, EntityType, DeviceName, AccountUpn, FileName, SHA256, RemoteIP, RemoteUrl',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-attack-disruption',
      t: 'Automatic attack disruption actions',
      p: ['Triage', 'Containment'],
      d: 'What Defender contained on its own: accounts suspended, devices isolated and the reason behind each action.',
      k: 'disruptionandresponseevents attack disruption automatic containment isolated user disabled action response',
      days: 30,
      req: 'Microsoft Defender XDR with automatic attack disruption (this table is in preview).',
      q: ctx => [
        'DisruptionAndResponseEvents',
        '| where Timestamp > ' + ctx.ago,
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-behaviour-analytics',
      t: 'Behaviour analytics findings',
      p: ['Triage', 'Identity'],
      d: 'The behaviour level signals from Defender for Cloud Apps and user analytics, which sit below the alert threshold.',
      k: 'behaviorinfo behaviorentities ueba behaviour anomaly cloud app security signals below alert preview',
      days: 14,
      req: 'Microsoft Defender for Cloud Apps (these tables are in preview).',
      q: ctx => [
        'BehaviorInfo',
        '| where Timestamp > ' + ctx.ago,
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-ioc-sweep',
      t: 'Sweep the estate for indicators',
      p: ['Triage', 'Collection'],
      d: 'Takes a list of hashes, addresses and domains and searches every relevant table in one pass.',
      k: 'ioc sweep indicators hash ip domain union search all tables threat intelligence hunt compromise assessment',
      days: 30,
      vars: [['hashes', 'SHA256 hashes (comma separated)', '', 'text'], ['addresses', 'IP addresses or domains (comma separated)', '', 'text']],
      q: ctx => {
        const list = v => (v ? v.split(',').map(s => s.trim()).filter(Boolean) : []);
        const hashes = list(ctx.v('hashes'));
        const addrs = list(ctx.v('addresses'));
        return [
          'let hashes = dynamic([' + (hashes.length ? '"' + hashes.join('","') + '"' : '""') + ']);',
          'let addresses = dynamic([' + (addrs.length ? '"' + addrs.join('","') + '"' : '""') + ']);',
          'union isfuzzy=true',
          '    (DeviceFileEvents',
          '        | where Timestamp > ' + ctx.ago,
          '        | where SHA256 in~ (hashes)',
          '        | project Timestamp, Table = "DeviceFileEvents", Entity = DeviceName, Detail = strcat(FolderPath, FileName)),',
          '    (DeviceProcessEvents',
          '        | where Timestamp > ' + ctx.ago,
          '        | where SHA256 in~ (hashes)',
          '        | project Timestamp, Table = "DeviceProcessEvents", Entity = DeviceName, Detail = ProcessCommandLine),',
          '    (DeviceNetworkEvents',
          '        | where Timestamp > ' + ctx.ago,
          '        | where RemoteIP in~ (addresses) or RemoteUrl has_any (addresses)',
          '        | project Timestamp, Table = "DeviceNetworkEvents", Entity = DeviceName, Detail = strcat(RemoteUrl, " ", RemoteIP, ":", RemotePort)),',
          '    (EmailEvents',
          '        | where Timestamp > ' + ctx.ago,
          '        | where SenderIPv4 in~ (addresses) or SenderFromDomain has_any (addresses)',
          '        | project Timestamp, Table = "EmailEvents", Entity = RecipientEmailAddress, Detail = strcat(SenderFromAddress, " : ", Subject)),',
          '    (CloudAppEvents',
          '        | where Timestamp > ' + ctx.ago,
          '        | where IPAddress in~ (addresses)',
          '        | project Timestamp, Table = "CloudAppEvents", Entity = AccountDisplayName, Detail = strcat(Application, " ", ActionType))',
          '| sort by Timestamp desc'
        ];
      }
    },
    {
      id: 'kql-device-timeline',
      t: 'Full timeline for one device',
      p: ['Triage', 'Endpoint'],
      d: 'Processes, files, registry, network and logons for a single machine, merged into one ordered list.',
      k: 'device timeline union all tables one machine investigation forensics order of events endpoint story',
      days: 3, ent: DEVICE,
      q: ctx => [
        'let device = "' + (ctx.ent || 'PC-001') + '";',
        'union isfuzzy=true',
        '    (DeviceProcessEvents',
        '        | where Timestamp > ' + ctx.ago + ' and DeviceName has device',
        '        | project Timestamp, Table = "Process", Account = AccountName, Detail = ProcessCommandLine),',
        '    (DeviceFileEvents',
        '        | where Timestamp > ' + ctx.ago + ' and DeviceName has device',
        '        | project Timestamp, Table = "File", Account = InitiatingProcessAccountName, Detail = strcat(ActionType, " ", FolderPath, FileName)),',
        '    (DeviceRegistryEvents',
        '        | where Timestamp > ' + ctx.ago + ' and DeviceName has device',
        '        | project Timestamp, Table = "Registry", Account = InitiatingProcessAccountName, Detail = strcat(ActionType, " ", RegistryKey, " ", RegistryValueName)),',
        '    (DeviceNetworkEvents',
        '        | where Timestamp > ' + ctx.ago + ' and DeviceName has device',
        '        | project Timestamp, Table = "Network", Account = InitiatingProcessAccountName, Detail = strcat(InitiatingProcessFileName, " -> ", RemoteUrl, " ", RemoteIP, ":", RemotePort)),',
        '    (DeviceLogonEvents',
        '        | where Timestamp > ' + ctx.ago + ' and DeviceName has device',
        '        | project Timestamp, Table = "Logon", Account = AccountName, Detail = strcat(ActionType, " ", LogonType, " from ", RemoteIP))',
        '| sort by Timestamp desc'
      ]
    },
    {
      id: 'kql-custom-detection-template',
      t: 'Template for a custom detection rule',
      p: ['Detection engineering'],
      d: 'The shape a query must have to become a custom detection: a time filter, the entity columns and ReportId.',
      k: 'custom detection rule required columns reportid deviceid timestamp alert impacted entities detection engineering',
      days: 1,
      opts: [['device', 'Device based rule', true], ['account', 'Account based rule', false], ['mailbox', 'Mailbox based rule', false]],
      q: ctx => {
        const cols = ['Timestamp', 'ReportId'];
        if (ctx.on('device')) cols.push('DeviceId', 'DeviceName');
        if (ctx.on('account')) cols.push('AccountObjectId', 'AccountUpn', 'AccountSid');
        if (ctx.on('mailbox')) cols.push('RecipientEmailAddress', 'NetworkMessageId');
        return [
          '// A custom detection query must return Timestamp, ReportId and the entity columns it alerts on.',
          '// Keep the time filter at or below the rule frequency.',
          'DeviceProcessEvents',
          '| where Timestamp > ' + ctx.ago,
          '| where ProcessCommandLine has "REPLACE-WITH-YOUR-CONDITION"',
          '| extend Reason = "Short description that lands in the alert"',
          '| project ' + cols.join(', ') + ', Reason, ProcessCommandLine, AccountName, InitiatingProcessFileName'
        ];
      }
    },
    {
      id: 'kql-hunt-coverage-check',
      t: 'Which tables actually have data',
      p: ['Triage', 'Detection engineering'],
      d: 'Counts rows per table for the window so you know what telemetry you really have before trusting a negative result.',
      k: 'coverage table row count telemetry available data union checking blind spot licensing onboarding verify',
      days: 1, noLimit: true,
      q: ctx => [
        'let lookback = ' + ctx.days + 'd;',
        'union withsource = TableName isfuzzy=true',
        '    (DeviceProcessEvents | where Timestamp > ago(lookback) | project Timestamp),',
        '    (DeviceNetworkEvents | where Timestamp > ago(lookback) | project Timestamp),',
        '    (DeviceFileEvents | where Timestamp > ago(lookback) | project Timestamp),',
        '    (DeviceLogonEvents | where Timestamp > ago(lookback) | project Timestamp),',
        '    (DeviceRegistryEvents | where Timestamp > ago(lookback) | project Timestamp),',
        '    (EmailEvents | where Timestamp > ago(lookback) | project Timestamp),',
        '    (UrlClickEvents | where Timestamp > ago(lookback) | project Timestamp),',
        '    (CloudAppEvents | where Timestamp > ago(lookback) | project Timestamp),',
        '    (EntraIdSignInEvents | where Timestamp > ago(lookback) | project Timestamp),',
        '    (IdentityLogonEvents | where Timestamp > ago(lookback) | project Timestamp),',
        '    (IdentityDirectoryEvents | where Timestamp > ago(lookback) | project Timestamp),',
        '    (AlertInfo | where Timestamp > ago(lookback) | project Timestamp),',
        '    (GraphAPIAuditEvents | where Timestamp > ago(lookback) | project Timestamp),',
        '    (CloudAuditEvents | where Timestamp > ago(lookback) | project Timestamp)',
        '| summarize Rows = count(), FirstEvent = min(Timestamp), LastEvent = max(Timestamp) by TableName',
        '| sort by Rows desc'
      ]
    }
  );

  /* --- more hunting specs are appended above this marker --- */

  SPECS.forEach(s => SCRIPTS.push(s));
})();

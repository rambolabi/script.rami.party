'use strict';

/* ============================================================================
   Microsoft 365 / Entra ID incident response library.

   Three entry shapes:
     kind 'ual'    Search-UnifiedAuditLog queries built by ualBuild().
                   Keys: ops (operations), rec (RecordType), cols (extra
                   columns over the parsed AuditData), days, ip, free, obj.
     kind 'ps'     any other PowerShell, custom build(sel) with more[] options.
     kind 'kql'    Defender XDR / Sentinel hunting queries, build(sel) or code.

   Operation names come from the Purview "Audited activities" reference. Some
   of them genuinely end in a period (for example "Add service principal.")
   and must keep it, which is why every operation is quoted in -Operations.
   ========================================================================== */

(function () {
  const q = v => String(v == null ? '' : v).trim().replace(/'/g, "''");
  const num = (v, fallback) => (parseInt(v, 10) > 0 ? parseInt(v, 10) : fallback);
  const EXO = 'ExchangeOnlineManagement module, connected with Connect-ExchangeOnline.';
  const GRAPH = 'Microsoft.Graph module, connected with Connect-MgGraph and the right read scopes.';
  const HUNT = 'Advanced hunting in the Microsoft Defender portal, or Microsoft Sentinel.';

  /* Columns available on every unified audit log query. The expressions run
     inside a ForEach-Object where $_ is the record and $data the parsed AuditData. */
  const UAL_BASE = [
    ['Time', '$_.CreationDate', true],
    ['User', '$_.UserIds', true],
    ['Operation', '$_.Operations', true],
    ['ResultStatus', '$data.ResultStatus'],
    ['ClientIP', '$data.ClientIP', true],
    ['UserAgent', '$data.UserAgent'],
    ['ClientInfo', '$data.ClientInfoString'],
    ['Workload', '$data.Workload'],
    ['RecordType', '$_.RecordType'],
    ['ObjectId', '$data.ObjectId'],
    ['AppId', '$data.AppId'],
    ['SessionId', '$data.SessionId'],
    ['RawAuditData', '$_.AuditData']
  ];

  function ualColumns(spec) {
    const extra = (spec.cols || []).map(c => ({ id: c[0], label: c[0], expr: c[1], default: c[2] !== false, hint: c[3] }));
    const base = UAL_BASE.map(c => ({ id: c[0], label: c[0], expr: c[1], default: !!c[2] }));
    // Script specific columns sit between the identity columns and the rest.
    return base.slice(0, 3).concat(extra, base.slice(3));
  }

  function pad(name, width) {
    return name + ' '.repeat(Math.max(1, width - name.length));
  }

  function ualBuild(spec, cols, sel) {
    const days = num(sel.days, spec.days || 7);
    const lines = [
      '$start = (Get-Date).AddDays(-' + days + ')',
      '$end = Get-Date'
    ];

    const args = ['-StartDate $start -EndDate $end'];
    if (spec.rec) args.push('-RecordType ' + spec.rec);
    const ops = spec.ops && sel.ops ? spec.ops.filter(o => sel.ops.has(o)) : (spec.ops || []);
    if (ops.length) args.push('-Operations ' + ops.map(o => '"' + o + '"').join(', '));
    if (spec.user !== false && q(sel.user)) args.push("-UserIds '" + q(sel.user) + "'");
    if (spec.ip && q(sel.ip)) args.push("-IPAddresses '" + q(sel.ip) + "'");
    if (spec.free && q(sel.free)) args.push("-FreeText '" + q(sel.free) + "'");
    if (spec.obj && q(sel.obj)) args.push("-ObjectIds '" + q(sel.obj) + "'");
    args.push('-ResultSize 5000');
    if (sel.search.has('formatted')) args.push('-Formatted');
    if (sel.search.has('completeness')) args.push('-HighCompleteness');

    const call = 'Search-UnifiedAuditLog ' + args.join(' ');
    if (sel.search.has('paging')) {
      lines.push('$session = [guid]::NewGuid().ToString()');
      lines.push('$records = @()');
      lines.push('do {');
      lines.push('    $page = ' + call + ' -SessionId $session -SessionCommand ReturnLargeSet');
      lines.push('    $records += $page');
      lines.push('} while ($page.Count -gt 0)');
    } else {
      lines.push('$records = ' + call);
    }

    const picked = cols.filter(c => sel.columns.has(c.id));
    const width = Math.max.apply(null, picked.map(c => c.label.length).concat([4])) + 1;
    lines.push('$report = $records | ForEach-Object {');
    lines.push('    $data = $_.AuditData | ConvertFrom-Json');
    lines.push('    [pscustomobject]@{');
    picked.forEach(c => lines.push('        ' + pad(c.label, width) + ' = ' + c.expr));
    lines.push('    }');
    lines.push('}');

    const summary = {
      user: 'Group-Object User -NoElement | Sort-Object Count -Descending',
      ip: 'Group-Object ClientIP -NoElement | Sort-Object Count -Descending',
      op: 'Group-Object Operation -NoElement | Sort-Object Count -Descending',
      day: "Group-Object { $_.Time.ToString('yyyy-MM-dd') } -NoElement | Sort-Object Name"
    }[sel.summary];

    if (sel.output === 'count') {
      lines.push('@($report).Count');
      return lines.join('\n');
    }
    const file = (spec.id || 'ual').replace(/[^a-z0-9]+/gi, '-');
    const tail = {
      table: 'Format-Table -AutoSize',
      list: 'Format-List',
      grid: "Out-GridView -Title '" + q(spec.t) + "'",
      csv: 'Export-Csv -Path .\\' + file + '.csv -NoTypeInformation -Encoding UTF8',
      json: 'ConvertTo-Json -Depth 10 | Out-File .\\' + file + '.json -Encoding UTF8'
    }[sel.output];

    const stages = ['$report'];
    if (summary) stages.push(summary);
    else stages.push('Sort-Object Time -Descending');
    if (tail) stages.push(tail);
    lines.push(stages.join(' |\n    '));
    return lines.join('\n');
  }

  function ualEntry(spec) {
    const cols = ualColumns(spec);
    const opts = [];
    opts.push({ id: 'days', label: 'Look back (days)', type: 'number', placeholder: String(spec.days || 7), value: String(spec.days || 7), hint: 'The unified audit log keeps 180 days by default.' });
    if (spec.user !== false) opts.push({ id: 'user', label: 'User (UPN, empty for all)', type: 'text', placeholder: 'jdoe@contoso.com' });
    if (spec.ip) opts.push({ id: 'ip', label: 'Source IP address (optional)', type: 'text', placeholder: '203.0.113.10' });
    if (spec.free) opts.push({ id: 'free', label: 'Free text (optional)', type: 'text', placeholder: 'invoice' });
    if (spec.obj) opts.push({ id: 'obj', label: 'Object ID (optional)', type: 'text', placeholder: 'https://contoso.sharepoint.com/sites/hr/*' });
    if (spec.ops && spec.ops.length > 1) {
      opts.push({
        id: 'ops', label: 'Operations', type: 'multi', wide: spec.ops.length > 4,
        hint: 'Audit operations to search for. Clear all to search every operation.',
        items: spec.ops.map(o => ({ id: o, label: o, default: true }))
      });
    }
    opts.push({
      id: 'columns', label: 'Columns', type: 'multi', wide: true,
      hint: 'Fields taken from the record and its parsed AuditData.',
      items: cols.map(c => ({ id: c.id, label: c.label, hint: c.hint, default: c.default }))
    });
    opts.push({
      id: 'summary', label: 'Summary', type: 'single', items: [
        { id: 'none', label: 'Full detail', default: true },
        { id: 'user', label: 'Count per user' },
        { id: 'ip', label: 'Count per source IP' },
        { id: 'op', label: 'Count per operation' },
        { id: 'day', label: 'Count per day' }
      ]
    });
    opts.push({
      id: 'search', label: 'Search options', type: 'multi', items: [
        { id: 'paging', label: 'Page through every result', default: true, hint: 'Required for more than 100 records.' },
        { id: 'formatted', label: 'Readable record types (-Formatted)', default: true },
        { id: 'completeness', label: 'Slower but more complete (-HighCompleteness)' }
      ]
    });
    opts.push({
      id: 'output', label: 'Output', type: 'single', items: [
        { id: 'objects', label: 'Plain objects' },
        { id: 'count', label: 'Count only' },
        { id: 'table', label: 'Table (Format-Table)', default: true },
        { id: 'list', label: 'List (Format-List)' },
        { id: 'grid', label: 'Grid view (Out-GridView)' },
        { id: 'csv', label: 'CSV file (Export-Csv)' },
        { id: 'json', label: 'JSON file (full detail)' }
      ]
    });
    return {
      id: spec.id,
      title: spec.t,
      language: 'PowerShell',
      purposes: ['Incident Response'].concat(spec.p || []),
      description: spec.d,
      requires: spec.req || EXO,
      keywords: (spec.k || '') + ' unified audit log search-unifiedauditlog purview',
      options: opts,
      build: sel => ualBuild(spec, cols, sel)
    };
  }

  function plainEntry(spec) {
    const entry = {
      id: spec.id,
      title: spec.t,
      language: spec.kind === 'kql' ? 'KQL' : 'PowerShell',
      purposes: ['Incident Response'].concat(spec.p || []),
      description: spec.d,
      requires: spec.req || (spec.kind === 'kql' ? HUNT : EXO),
      keywords: spec.k || ''
    };
    if (spec.code) entry.code = spec.code;
    else { entry.options = spec.more || []; entry.build = spec.build; }
    return entry;
  }

  const SPECS = [];
  const add = (...items) => items.forEach(i => SPECS.push(i));

  /* ------------------------------------------------ collection and triage */

  add(
    {
      kind: 'ps',
      id: 'ir-connect-workspace',
      t: 'Connect the investigation modules',
      p: ['Collection'],
      d: 'Opens the sessions every Microsoft 365 investigation needs: Exchange Online, Security and Compliance, and Microsoft Graph with read scopes.',
      k: 'connect-exchangeonline connect-mggraph connect-ippssession scopes install-module prepare investigation',
      req: 'ExchangeOnlineManagement and Microsoft.Graph modules, and an account with the reader roles.',
      more: [
        { id: 'upn', label: 'Investigator account', type: 'text', placeholder: 'ir-admin@contoso.com' },
        {
          id: 'targets', label: 'Connect to', type: 'multi', items: [
            { id: 'exo', label: 'Exchange Online', default: true },
            { id: 'ipps', label: 'Security and Compliance (Purview)', default: true },
            { id: 'graph', label: 'Microsoft Graph', default: true }
          ]
        },
        { id: 'install', label: 'First run', type: 'multi', items: [{ id: 'modules', label: 'Install the modules first' }] }
      ],
      build: sel => {
        const upn = q(sel.upn) || 'ir-admin@contoso.com';
        const lines = [];
        if (sel.install.has('modules')) {
          lines.push('Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force');
          lines.push('Install-Module Microsoft.Graph -Scope CurrentUser -Force');
        }
        if (sel.targets.has('exo')) lines.push("Connect-ExchangeOnline -UserPrincipalName '" + upn + "'");
        if (sel.targets.has('ipps')) lines.push("Connect-IPPSSession -UserPrincipalName '" + upn + "'");
        if (sel.targets.has('graph')) {
          lines.push('$scopes = @(');
          lines.push("    'AuditLog.Read.All'");
          lines.push("    'Directory.Read.All'");
          lines.push("    'User.Read.All'");
          lines.push("    'Application.Read.All'");
          lines.push("    'Policy.Read.All'");
          lines.push("    'IdentityRiskyUser.Read.All'");
          lines.push(')');
          lines.push('Connect-MgGraph -Scopes $scopes');
        }
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'ir-audit-status',
      t: 'Is auditing actually on?',
      p: ['Collection', 'Purview'],
      d: 'First question of every investigation: check tenant wide audit ingestion, the mailbox audit defaults and how long records are kept.',
      k: 'get-adminauditlogconfig unifiedauditlogingestionenabled auditdisabled mailbox auditing retention e5 turn on',
      more: [
        {
          id: 'checks', label: 'Check', type: 'multi', items: [
            { id: 'tenant', label: 'Tenant audit ingestion', default: true },
            { id: 'bypass', label: 'Mailbox audit bypass accounts', default: true },
            { id: 'mailboxes', label: 'Per mailbox audit settings', default: true },
            { id: 'retention', label: 'Audit retention policies', default: true }
          ]
        },
        { id: 'user', label: 'Mailbox to check (empty for all)', type: 'text', placeholder: 'jdoe@contoso.com' }
      ],
      build: sel => {
        const user = q(sel.user);
        const lines = [];
        if (sel.checks.has('tenant')) {
          lines.push('Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled, AdminAuditLogEnabled');
          lines.push('Get-OrganizationConfig | Format-List AuditDisabled, Name');
        }
        if (sel.checks.has('bypass')) {
          lines.push('Get-MailboxAuditBypassAssociation -ResultSize Unlimited |');
          lines.push('    Where-Object { $_.AuditBypassEnabled } |');
          lines.push('    Format-Table Name, AuditBypassEnabled -AutoSize');
        }
        if (sel.checks.has('mailboxes')) {
          lines.push('Get-Mailbox ' + (user ? "-Identity '" + user + "'" : '-ResultSize Unlimited') + ' |');
          lines.push('    Select-Object UserPrincipalName, AuditEnabled, AuditLogAgeLimit,');
          lines.push("        @{N='AuditOwner';E={$_.AuditOwner -join ', '}},");
          lines.push("        @{N='AuditDelegate';E={$_.AuditDelegate -join ', '}},");
          lines.push("        @{N='AuditAdmin';E={$_.AuditAdmin -join ', '}} |");
          lines.push('    Format-Table -AutoSize');
        }
        if (sel.checks.has('retention')) {
          lines.push('Get-UnifiedAuditLogRetentionPolicy | Format-Table Name, RecordTypes, RetentionDuration, Priority, Enabled -AutoSize');
        }
        return lines.join('\n');
      }
    },
    {
      kind: 'ual',
      id: 'ir-ual-user-timeline',
      t: 'Full activity timeline for one account',
      p: ['Collection', 'Identity'],
      d: 'Everything the unified audit log holds for one account across all workloads, the backbone of a business email compromise timeline.',
      k: 'timeline all activity user compromise bec investigation everything workload',
      days: 30, ip: 1, free: 1,
      cols: [['Details', "($data | ConvertTo-Json -Compress -Depth 5)", false, 'The complete AuditData object as one JSON line.']]
    },
    {
      kind: 'ual',
      id: 'ir-ual-record-type-summary',
      t: 'What kind of activity happened',
      p: ['Collection', 'Triage'],
      d: 'Counts audit records per workload and operation so you can see where to dig before pulling detail.',
      k: 'triage overview summary recordtype workload count group first look scope',
      days: 7, user: true,
      cols: []
    },
    {
      kind: 'ual',
      id: 'ir-ual-by-ip',
      t: 'Everything done from an IP address',
      p: ['Collection', 'Identity'],
      d: 'Pivots on a suspect source address to find every account and action that came from it.',
      k: 'ipaddresses source ip pivot attacker infrastructure tor vpn address',
      days: 30, ip: 1,
      cols: []
    },
    {
      kind: 'ual',
      id: 'ir-ual-free-text',
      t: 'Free text search of the audit log',
      p: ['Collection'],
      d: 'Searches the raw audit records for a string, useful for a file name, a domain or a rule name you already know.',
      k: 'freetext keyword search string ioc indicator hunt raw',
      days: 30, free: 1,
      cols: []
    },
    {
      kind: 'ps',
      id: 'ir-ual-bulk-export',
      t: 'Bulk export the audit log to CSV',
      p: ['Collection', 'Purview'],
      d: 'Walks a long date range in slices and writes every record to disk, the way to get evidence out before retention expires.',
      k: 'export csv evidence preservation bulk slice paging retention 5000 limit chunks',
      more: [
        { id: 'days', label: 'Days back', type: 'number', placeholder: '90', value: '90' },
        { id: 'slice', label: 'Hours per slice', type: 'number', placeholder: '6', value: '6', hint: 'Smaller slices avoid the 50,000 record ceiling per search.' },
        { id: 'user', label: 'User (empty for all)', type: 'text', placeholder: 'jdoe@contoso.com' },
        { id: 'path', label: 'Output file', type: 'text', placeholder: '.\\UAL-export.csv' }
      ],
      build: sel => {
        const user = q(sel.user);
        return [
          '$start = (Get-Date).AddDays(-' + num(sel.days, 90) + ')',
          '$end = Get-Date',
          '$slice = [TimeSpan]::FromHours(' + num(sel.slice, 6) + ')',
          "$path = '" + (q(sel.path) || '.\\UAL-export.csv') + "'",
          '$cursor = $start',
          'while ($cursor -lt $end) {',
          '    $stop = [DateTime]::Min($cursor.Add($slice), $end)',
          '    $session = [guid]::NewGuid().ToString()',
          '    do {',
          '        $page = Search-UnifiedAuditLog -StartDate $cursor -EndDate $stop ' + (user ? "-UserIds '" + user + "' " : '') + '`',
          '            -ResultSize 5000 -SessionId $session -SessionCommand ReturnLargeSet',
          '        if ($page) { $page | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8 -Append }',
          '    } while ($page.Count -gt 0)',
          '    Write-Host "$cursor to $stop done"',
          '    $cursor = $stop',
          '}'
        ].join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'ir-audit-retention-policy',
      t: 'Extend audit log retention',
      p: ['Purview', 'Collection'],
      d: 'Creates a retention policy so the records of an incident survive past the default window while the investigation runs.',
      k: 'new-unifiedauditlogretentionpolicy retention 10 years preserve evidence audit premium',
      req: 'Security and Compliance PowerShell (Connect-IPPSSession) and an Audit Premium licence.',
      more: [
        { id: 'name', label: 'Policy name', type: 'text', placeholder: 'IR-2026-retention' },
        { id: 'user', label: 'User (optional)', type: 'text', placeholder: 'jdoe@contoso.com' },
        {
          id: 'duration', label: 'Keep for', type: 'single', items: [
            { id: 'OneYear', label: 'One year', default: true },
            { id: 'ThreeYears', label: 'Three years' },
            { id: 'TenYears', label: 'Ten years' }
          ]
        },
        {
          id: 'mode', label: 'Action', type: 'single', items: [
            { id: 'list', label: 'List current policies', default: true },
            { id: 'create', label: 'Create the policy' }
          ]
        }
      ],
      build: sel => {
        if (sel.mode === 'list') return 'Get-UnifiedAuditLogRetentionPolicy | Format-Table Name, RecordTypes, UserIds, RetentionDuration, Priority -AutoSize';
        const name = q(sel.name) || 'IR-retention';
        const user = q(sel.user);
        return [
          'New-UnifiedAuditLogRetentionPolicy `',
          "    -Name '" + name + "' `",
          "    -Description 'Incident response evidence retention' `",
          (user ? "    -UserIds '" + user + "' `" : '    -RecordTypes ExchangeItem, AzureActiveDirectorySignIn `'),
          '    -RetentionDuration ' + sel.duration + ' `',
          '    -Priority 1'
        ].filter(Boolean).join('\n');
      }
    }
  );

  /* ------------------------------------------------------ Entra ID sign-ins */

  add(
    {
      kind: 'ps',
      id: 'entra-signins-user',
      t: 'Sign-in log for one account',
      p: ['Entra ID', 'Identity'],
      d: 'Pulls the Entra sign-in records for an account with location, app, client and conditional access result.',
      k: 'get-mgauditlogsignin sign-in logs interactive location ip conditional access app device',
      req: GRAPH,
      more: [
        { id: 'user', label: 'User (UPN)', type: 'text', placeholder: 'jdoe@contoso.com' },
        { id: 'days', label: 'Look back (days)', type: 'number', placeholder: '7', value: '7', hint: 'Entra keeps 30 days with a P1 or P2 licence, 7 days otherwise.' },
        {
          id: 'filters', label: 'Filter', type: 'multi', items: [
            { id: 'failed', label: 'Failed sign-ins only' },
            { id: 'interactive', label: 'Interactive sign-ins only' },
            { id: 'success', label: 'Successful sign-ins only' }
          ]
        },
        {
          id: 'output', label: 'Output', type: 'single', items: [
            { id: 'table', label: 'Table (Format-Table)', default: true },
            { id: 'csv', label: 'CSV file (Export-Csv)' },
            { id: 'grid', label: 'Grid view (Out-GridView)' },
            { id: 'ip', label: 'Count per IP address' },
            { id: 'country', label: 'Count per country' },
            { id: 'app', label: 'Count per application' }
          ]
        }
      ],
      build: sel => {
        const user = q(sel.user) || 'jdoe@contoso.com';
        const filters = ["userPrincipalName eq '" + user + "'", 'createdDateTime ge $cut'];
        if (sel.filters.has('failed')) filters.push('status/errorCode ne 0');
        if (sel.filters.has('success')) filters.push('status/errorCode eq 0');
        const lines = [
          "$cut = (Get-Date).AddDays(-" + num(sel.days, 7) + ").ToString('yyyy-MM-ddTHH:mm:ssZ')",
          '$signIns = Get-MgAuditLogSignIn -Filter "' + filters.join(' and ') + '" -All'
        ];
        if (sel.filters.has('interactive')) lines.push('$signIns = $signIns | Where-Object { $_.IsInteractive }');
        lines.push('$report = $signIns | Select-Object CreatedDateTime, UserPrincipalName, AppDisplayName,');
        lines.push('    IPAddress, ClientAppUsed, IsInteractive, ConditionalAccessStatus, RiskLevelDuringSignIn,');
        lines.push("    @{N='Country';E={$_.Location.CountryOrRegion}}, @{N='City';E={$_.Location.City}},");
        lines.push("    @{N='Error';E={$_.Status.ErrorCode}}, @{N='Reason';E={$_.Status.FailureReason}},");
        lines.push("    @{N='Device';E={$_.DeviceDetail.DisplayName}}, @{N='OS';E={$_.DeviceDetail.OperatingSystem}}");
        if (sel.output === 'ip') lines.push('$report | Group-Object IPAddress -NoElement | Sort-Object Count -Descending | Format-Table -AutoSize');
        else if (sel.output === 'country') lines.push('$report | Group-Object Country -NoElement | Sort-Object Count -Descending | Format-Table -AutoSize');
        else if (sel.output === 'app') lines.push('$report | Group-Object AppDisplayName -NoElement | Sort-Object Count -Descending | Format-Table -AutoSize');
        else if (sel.output === 'csv') lines.push('$report | Export-Csv -Path .\\SignIns.csv -NoTypeInformation -Encoding UTF8');
        else if (sel.output === 'grid') lines.push("$report | Out-GridView -Title 'Sign-in logs'");
        else lines.push('$report | Sort-Object CreatedDateTime -Descending | Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'entra-signins-device-code',
      t: 'Device code flow sign-ins',
      p: ['Entra ID', 'Identity', 'Phishing'],
      d: 'Device code authentication is rare in normal use and heavily abused for phishing, so every hit deserves a look.',
      k: 'device code flow devicecode phishing authenticationprotocol token theft aitm consent',
      req: GRAPH,
      more: [
        { id: 'days', label: 'Look back (days)', type: 'number', placeholder: '30', value: '30' },
        { id: 'user', label: 'User (optional)', type: 'text', placeholder: 'jdoe@contoso.com' },
        {
          id: 'extra', label: 'Also report', type: 'multi', items: [
            { id: 'success', label: 'Successful attempts only', default: true },
            { id: 'apps', label: 'Count per application', default: true },
            { id: 'ips', label: 'Count per IP address' }
          ]
        }
      ],
      build: sel => {
        const user = q(sel.user);
        const filters = ["authenticationProtocol eq 'deviceCode'", 'createdDateTime ge $cut'];
        if (user) filters.push("userPrincipalName eq '" + user + "'");
        if (sel.extra.has('success')) filters.push('status/errorCode eq 0');
        const lines = [
          "$cut = (Get-Date).AddDays(-" + num(sel.days, 30) + ").ToString('yyyy-MM-ddTHH:mm:ssZ')",
          '$signIns = Get-MgAuditLogSignIn -Filter "' + filters.join(' and ') + '" -All',
          '$report = $signIns | Select-Object CreatedDateTime, UserPrincipalName, AppDisplayName, ResourceDisplayName,',
          "    IPAddress, @{N='Country';E={$_.Location.CountryOrRegion}}, UserAgent,",
          "    @{N='Error';E={$_.Status.ErrorCode}}, ConditionalAccessStatus",
          '$report | Sort-Object CreatedDateTime -Descending | Format-Table -AutoSize'
        ];
        if (sel.extra.has('apps')) lines.push('$report | Group-Object AppDisplayName -NoElement | Sort-Object Count -Descending | Format-Table -AutoSize');
        if (sel.extra.has('ips')) lines.push('$report | Group-Object IPAddress -NoElement | Sort-Object Count -Descending | Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'entra-signins-legacy-auth',
      t: 'Legacy authentication sign-ins',
      p: ['Entra ID', 'Identity'],
      d: 'IMAP, POP, SMTP and ActiveSync cannot do modern authentication, so they are the usual way around MFA.',
      k: 'clientappused imap pop smtp activesync legacy basic authentication mfa bypass',
      req: GRAPH,
      more: [
        { id: 'days', label: 'Look back (days)', type: 'number', placeholder: '14', value: '14' },
        {
          id: 'protocols', label: 'Protocols', type: 'multi', items: [
            { id: 'IMAP4', label: 'IMAP', default: true },
            { id: 'POP3', label: 'POP', default: true },
            { id: 'SMTP', label: 'SMTP', default: true },
            { id: 'Exchange ActiveSync', label: 'Exchange ActiveSync', default: true },
            { id: 'Other clients', label: 'Other legacy clients', default: true },
            { id: 'Autodiscover', label: 'Autodiscover' }
          ]
        },
        { id: 'extra', label: 'Also report', type: 'multi', items: [{ id: 'users', label: 'Count per user', default: true }] }
      ],
      build: sel => {
        const list = Array.from(sel.protocols).map(p => "'" + q(p) + "'").join(', ');
        const lines = [
          "$cut = (Get-Date).AddDays(-" + num(sel.days, 14) + ").ToString('yyyy-MM-ddTHH:mm:ssZ')",
          '$legacy = @(' + (list || "'IMAP4', 'POP3'") + ')',
          '$signIns = Get-MgAuditLogSignIn -Filter "createdDateTime ge $cut" -All',
          '$report = $signIns |',
          '    Where-Object { $_.ClientAppUsed -in $legacy } |',
          "    Select-Object CreatedDateTime, UserPrincipalName, ClientAppUsed, AppDisplayName, IPAddress,",
          "        @{N='Country';E={$_.Location.CountryOrRegion}}, @{N='Error';E={$_.Status.ErrorCode}}",
          '$report | Sort-Object CreatedDateTime -Descending | Format-Table -AutoSize'
        ];
        if (sel.extra.has('users')) lines.push('$report | Group-Object UserPrincipalName, ClientAppUsed -NoElement | Sort-Object Count -Descending | Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'entra-signins-failed',
      t: 'Failed sign-ins and password spray',
      p: ['Entra ID', 'Identity'],
      d: 'Groups failed sign-ins by error code, source address and account, the shape that exposes spraying and brute force.',
      k: 'password spray brute force failed 50126 50053 50076 error code lockout attack pattern',
      req: GRAPH,
      more: [
        { id: 'days', label: 'Look back (days)', type: 'number', placeholder: '3', value: '3' },
        { id: 'min', label: 'Minimum attempts per source', type: 'number', placeholder: '10', value: '10' },
        {
          id: 'view', label: 'View', type: 'single', items: [
            { id: 'ip', label: 'Per source IP', default: true },
            { id: 'user', label: 'Per targeted account' },
            { id: 'error', label: 'Per error code' },
            { id: 'detail', label: 'Every attempt' }
          ]
        }
      ],
      build: sel => {
        const lines = [
          "$cut = (Get-Date).AddDays(-" + num(sel.days, 3) + ").ToString('yyyy-MM-ddTHH:mm:ssZ')",
          '$failed = Get-MgAuditLogSignIn -Filter "createdDateTime ge $cut and status/errorCode ne 0" -All',
          '$report = $failed | Select-Object CreatedDateTime, UserPrincipalName, AppDisplayName, IPAddress,',
          "    @{N='Country';E={$_.Location.CountryOrRegion}}, @{N='Error';E={$_.Status.ErrorCode}},",
          "    @{N='Reason';E={$_.Status.FailureReason}}"
        ];
        const min = num(sel.min, 10);
        if (sel.view === 'ip') {
          lines.push('$report | Group-Object IPAddress |');
          lines.push('    Where-Object { $_.Count -ge ' + min + ' } |');
          lines.push("    Select-Object Count, Name, @{N='Accounts';E={($_.Group.UserPrincipalName | Sort-Object -Unique).Count}} |");
          lines.push('    Sort-Object Count -Descending |');
          lines.push('    Format-Table -AutoSize');
        } else if (sel.view === 'user') {
          lines.push('$report | Group-Object UserPrincipalName -NoElement | Sort-Object Count -Descending | Format-Table -AutoSize');
        } else if (sel.view === 'error') {
          lines.push('$report | Group-Object Error, Reason -NoElement | Sort-Object Count -Descending | Format-Table -AutoSize');
        } else {
          lines.push('$report | Sort-Object CreatedDateTime -Descending | Format-Table -AutoSize');
        }
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'entra-signins-impossible-travel',
      t: 'Sign-ins from unusual countries',
      p: ['Entra ID', 'Identity'],
      d: 'Lists the countries an account signed in from and flags the ones outside your expected list.',
      k: 'impossible travel geography country location anomalous atypical travel foreign',
      req: GRAPH,
      more: [
        { id: 'user', label: 'User (empty for all)', type: 'text', placeholder: 'jdoe@contoso.com' },
        { id: 'days', label: 'Look back (days)', type: 'number', placeholder: '14', value: '14' },
        { id: 'home', label: 'Expected countries (comma separated)', type: 'text', placeholder: 'BE, NL, FR' },
        { id: 'flags', label: 'Filter', type: 'multi', items: [{ id: 'successOnly', label: 'Successful sign-ins only', default: true }] }
      ],
      build: sel => {
        const user = q(sel.user);
        const home = q(sel.home) || 'BE, NL';
        const filters = ['createdDateTime ge $cut'];
        if (user) filters.push("userPrincipalName eq '" + user + "'");
        if (sel.flags.has('successOnly')) filters.push('status/errorCode eq 0');
        return [
          "$cut = (Get-Date).AddDays(-" + num(sel.days, 14) + ").ToString('yyyy-MM-ddTHH:mm:ssZ')",
          "$expected = '" + home + "' -split ',' | ForEach-Object { $_.Trim() }",
          '$signIns = Get-MgAuditLogSignIn -Filter "' + filters.join(' and ') + '" -All',
          '$signIns |',
          "    Select-Object CreatedDateTime, UserPrincipalName, IPAddress, AppDisplayName,",
          "        @{N='Country';E={$_.Location.CountryOrRegion}}, @{N='City';E={$_.Location.City}} |",
          '    Where-Object { $_.Country -and $_.Country -notin $expected } |',
          '    Sort-Object UserPrincipalName, CreatedDateTime |',
          '    Format-Table -AutoSize'
        ].join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'entra-signins-service-principal',
      t: 'Service principal sign-ins',
      p: ['Entra ID', 'Applications'],
      d: 'Application sign-ins have no user and no MFA, so a stolen client secret shows up only here.',
      k: 'serviceprincipalsignins app-only client secret certificate workload identity non-interactive daemon',
      req: GRAPH,
      more: [
        { id: 'days', label: 'Look back (days)', type: 'number', placeholder: '14', value: '14' },
        { id: 'app', label: 'Application name (optional)', type: 'text', placeholder: 'Contoso Sync' },
        {
          id: 'view', label: 'View', type: 'single', items: [
            { id: 'detail', label: 'Every sign-in', default: true },
            { id: 'app', label: 'Count per application' },
            { id: 'ip', label: 'Count per IP address' }
          ]
        }
      ],
      build: sel => {
        const app = q(sel.app);
        const lines = [
          "$cut = (Get-Date).AddDays(-" + num(sel.days, 14) + ").ToString('yyyy-MM-ddTHH:mm:ssZ')",
          '$signIns = Get-MgBetaAuditLogSignIn -Filter "createdDateTime ge $cut and signInEventTypes/any(t: t eq \'servicePrincipal\')" -All',
          '$report = $signIns | Select-Object CreatedDateTime, ServicePrincipalName, ServicePrincipalId, AppId,',
          "    ResourceDisplayName, IPAddress, @{N='Country';E={$_.Location.CountryOrRegion}},",
          "    @{N='Error';E={$_.Status.ErrorCode}}"
        ];
        if (app) lines.push("$report = $report | Where-Object { $_.ServicePrincipalName -like '*" + app + "*' }");
        if (sel.view === 'app') lines.push('$report | Group-Object ServicePrincipalName -NoElement | Sort-Object Count -Descending | Format-Table -AutoSize');
        else if (sel.view === 'ip') lines.push('$report | Group-Object IPAddress -NoElement | Sort-Object Count -Descending | Format-Table -AutoSize');
        else lines.push('$report | Sort-Object CreatedDateTime -Descending | Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'entra-risky-users',
      t: 'Risky users and risk detections',
      p: ['Entra ID', 'Identity'],
      d: 'Reads Identity Protection: which accounts are flagged, why, and whether anyone dismissed the risk.',
      k: 'get-mgriskyuser riskdetection identity protection leaked credentials anonymous ip risk state dismiss',
      req: 'Microsoft.Graph module with IdentityRiskyUser.Read.All and IdentityRiskEvent.Read.All, and Entra ID P2.',
      more: [
        {
          id: 'report', label: 'Report', type: 'single', items: [
            { id: 'users', label: 'Risky users', default: true },
            { id: 'detections', label: 'Risk detections' },
            { id: 'history', label: 'Risk history for one user' }
          ]
        },
        { id: 'user', label: 'User (for the history report)', type: 'text', placeholder: 'jdoe@contoso.com' },
        { id: 'flags', label: 'Filter', type: 'multi', items: [{ id: 'atRisk', label: 'Still at risk only', default: true }] }
      ],
      build: sel => {
        if (sel.report === 'history') {
          const user = q(sel.user) || 'jdoe@contoso.com';
          return [
            "$riskyUser = Get-MgRiskyUser -Filter \"userPrincipalName eq '" + user + "'\"",
            'Get-MgRiskyUserHistory -RiskyUserId $riskyUser.Id |',
            '    Select-Object RiskLastUpdatedDateTime, RiskLevel, RiskState, RiskDetail, @{N=\'Activity\';E={$_.Activity.EventTypes -join \', \'}} |',
            '    Format-Table -AutoSize'
          ].join('\n');
        }
        if (sel.report === 'detections') {
          const lines = ['$detections = Get-MgRiskDetection -All'];
          if (sel.flags.has('atRisk')) lines.push("$detections = $detections | Where-Object { $_.RiskState -eq 'atRisk' }");
          lines.push('$detections | Select-Object DetectedDateTime, UserPrincipalName, RiskEventType, RiskLevel, RiskState,');
          lines.push("    IPAddress, @{N='Country';E={$_.Location.CountryOrRegion}}, Activity, Source |");
          lines.push('    Sort-Object DetectedDateTime -Descending |');
          lines.push('    Format-Table -AutoSize');
          return lines.join('\n');
        }
        const lines = ['$risky = Get-MgRiskyUser -All'];
        if (sel.flags.has('atRisk')) lines.push("$risky = $risky | Where-Object { $_.RiskState -eq 'atRisk' }");
        lines.push('$risky | Select-Object UserPrincipalName, RiskLevel, RiskState, RiskDetail, RiskLastUpdatedDateTime |');
        lines.push('    Sort-Object RiskLastUpdatedDateTime -Descending |');
        lines.push('    Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'entra-user-auth-methods',
      t: 'MFA methods registered for a user',
      p: ['Entra ID', 'Identity', 'Persistence'],
      d: 'An attacker who enrols their own authenticator keeps access after a password reset, so compare this against what the user recognises.',
      k: 'get-mguserauthenticationmethod mfa registered authenticator phone fido persistence enrol second factor',
      req: 'Microsoft.Graph module with UserAuthenticationMethod.Read.All.',
      more: [
        { id: 'user', label: 'User (empty for all)', type: 'text', placeholder: 'jdoe@contoso.com' },
        { id: 'flags', label: 'Also show', type: 'multi', items: [{ id: 'registration', label: 'Registration details (Get-MgReportAuthenticationMethodUserRegistrationDetail)', default: true }] }
      ],
      build: sel => {
        const user = q(sel.user);
        const lines = [];
        if (user) {
          lines.push("Get-MgUserAuthenticationMethod -UserId '" + user + "' |");
          lines.push("    Select-Object Id, @{N='Type';E={$_.AdditionalProperties['@odata.type'] -replace '#microsoft.graph.', ''}},");
          lines.push("        @{N='Detail';E={$_.AdditionalProperties['displayName'], $_.AdditionalProperties['phoneNumber'] -ne $null -join ' '}} |");
          lines.push('    Format-Table -AutoSize');
        } else {
          lines.push('Get-MgUser -All | ForEach-Object {');
          lines.push('    $methods = Get-MgUserAuthenticationMethod -UserId $_.Id');
          lines.push('    [pscustomobject]@{');
          lines.push('        User    = $_.UserPrincipalName');
          lines.push("        Methods = ($methods.AdditionalProperties['@odata.type'] -replace '#microsoft.graph.', '') -join ', '");
          lines.push('    }');
          lines.push('} | Format-Table -AutoSize');
        }
        if (sel.flags.has('registration')) {
          lines.push('Get-MgReportAuthenticationMethodUserRegistrationDetail' + (user ? " -Filter \"userPrincipalName eq '" + user + "'\"" : ' -All') + ' |');
          lines.push('    Select-Object UserPrincipalName, IsMfaRegistered, IsMfaCapable, IsPasswordlessCapable, IsSsprRegistered,');
          lines.push("        @{N='Methods';E={$_.MethodsRegistered -join ', '}} |");
          lines.push('    Format-Table -AutoSize');
        }
        return lines.join('\n');
      }
    },
    {
      kind: 'ual',
      id: 'entra-mfa-changes',
      t: 'MFA and security info changes',
      p: ['Entra ID', 'Identity', 'Persistence'],
      d: 'Catches security info being registered, updated or deleted, the classic follow-up step after a successful phish.',
      k: 'security info registered mfa method added strongauthentication persistence enrol authenticator sspr',
      days: 30,
      ops: ['Update user.', 'Reset user password.', 'Change user password.', 'Set force change user password.'],
      cols: [
        ['Target', "$data.ObjectId", true],
        ['Actor', "$data.UserId", true],
        ['Changes', "($data.ModifiedProperties | ForEach-Object { $_.Name }) -join ', '", true, 'Which directory properties the record touched.']
      ]
    },
    {
      kind: 'ual',
      id: 'entra-role-changes',
      t: 'Directory role changes',
      p: ['Entra ID', 'Privilege escalation'],
      d: 'Somebody being added to a privileged role during an incident is escalation until proven otherwise.',
      k: 'add member to role global administrator privileged escalation pim role assignment directory admin',
      days: 30,
      ops: ['Add member to role.', 'Remove member from role.', 'Add eligible member to role.', 'Add member to role in PIM requested (permanent)'],
      cols: [
        ['Target', "$data.ObjectId", true],
        ['Role', "($data.ModifiedProperties | Where-Object { $_.Name -eq 'Role.DisplayName' }).NewValue", true],
        ['Actor', "$data.UserId", true]
      ]
    },
    {
      kind: 'ual',
      id: 'entra-user-admin-changes',
      t: 'Account creation and password resets',
      p: ['Entra ID', 'Persistence'],
      d: 'New accounts, deleted accounts and admin driven password resets, in one view with who did it.',
      k: 'add user delete user reset password backdoor account creation persistence admin change',
      days: 30,
      ops: ['Add user.', 'Delete user.', 'Update user.', 'Reset user password.', 'Change user password.', 'Change user license.', 'Disable account.', 'Enable account.'],
      cols: [
        ['Target', '$data.ObjectId', true],
        ['Actor', '$data.UserId', true],
        ['Changes', "($data.ModifiedProperties | ForEach-Object { $_.Name }) -join ', '", true]
      ]
    },
    {
      kind: 'ual',
      id: 'entra-domain-federation-changes',
      t: 'Domain and federation changes',
      p: ['Entra ID', 'Persistence'],
      d: 'Adding a domain or changing federation settings lets an attacker mint tokens for any user, so these records are always high severity.',
      k: 'set domain authentication federation settings golden saml add domain trust backdoor identity provider',
      days: 90,
      ops: ['Add domain to company.', 'Remove domain from company.', 'Set domain authentication.', 'Set federation settings on domain.', 'Update domain.', 'Verify domain.', 'Add partner to company.'],
      cols: [
        ['Target', '$data.ObjectId', true],
        ['Actor', '$data.UserId', true],
        ['Details', "($data.ModifiedProperties | ForEach-Object { $_.Name + '=' + $_.NewValue }) -join ' | '", true]
      ]
    },
    {
      kind: 'ps',
      id: 'entra-conditional-access-review',
      t: 'Conditional access policies and changes',
      p: ['Entra ID', 'Identity'],
      d: 'Exports the current conditional access policies and shows the recent edits, since a quietly weakened policy is a common persistence step.',
      k: 'conditional access policy changed disabled exclusion group bypass mfa legacy auth grant controls',
      req: 'Microsoft.Graph module with Policy.Read.All.',
      more: [
        {
          id: 'report', label: 'Report', type: 'single', items: [
            { id: 'policies', label: 'Current policies', default: true },
            { id: 'changes', label: 'Recent policy changes' },
            { id: 'exclusions', label: 'Users and groups excluded from policies' }
          ]
        },
        { id: 'days', label: 'Look back (days) for changes', type: 'number', placeholder: '30', value: '30' }
      ],
      build: sel => {
        if (sel.report === 'changes') {
          return [
            "$cut = (Get-Date).AddDays(-" + num(sel.days, 30) + ").ToString('yyyy-MM-ddTHH:mm:ssZ')",
            'Get-MgAuditLogDirectoryAudit -Filter "activityDateTime ge $cut and category eq \'Policy\'" -All |',
            "    Select-Object ActivityDateTime, ActivityDisplayName, @{N='Actor';E={$_.InitiatedBy.User.UserPrincipalName}},",
            "        @{N='Target';E={$_.TargetResources[0].DisplayName}}, Result |",
            '    Sort-Object ActivityDateTime -Descending |',
            '    Format-Table -AutoSize'
          ].join('\n');
        }
        if (sel.report === 'exclusions') {
          return [
            'Get-MgIdentityConditionalAccessPolicy -All | ForEach-Object {',
            '    [pscustomobject]@{',
            '        Policy         = $_.DisplayName',
            '        State          = $_.State',
            '        ExcludedUsers  = ($_.Conditions.Users.ExcludeUsers | ForEach-Object { (Get-MgUser -UserId $_ -ErrorAction SilentlyContinue).UserPrincipalName }) -join \', \'',
            '        ExcludedGroups = ($_.Conditions.Users.ExcludeGroups | ForEach-Object { (Get-MgGroup -GroupId $_ -ErrorAction SilentlyContinue).DisplayName }) -join \', \'',
            '    }',
            '} | Format-Table -AutoSize -Wrap'
          ].join('\n');
        }
        return [
          'Get-MgIdentityConditionalAccessPolicy -All |',
          '    Select-Object DisplayName, State, CreatedDateTime, ModifiedDateTime,',
          "        @{N='Users';E={$_.Conditions.Users.IncludeUsers -join ', '}},",
          "        @{N='Apps';E={$_.Conditions.Applications.IncludeApplications -join ', '}},",
          "        @{N='Grant';E={$_.GrantControls.BuiltInControls -join ', '}} |",
          '    Sort-Object State, DisplayName |',
          '    Format-Table -AutoSize'
        ].join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'entra-guest-and-new-accounts',
      t: 'New and guest accounts',
      p: ['Entra ID', 'Persistence'],
      d: 'Recently created members and guests, including who invited them and whether the invitation was accepted.',
      k: 'guest invitation b2b external new account created externaluserstate invite backdoor',
      req: GRAPH,
      more: [
        { id: 'days', label: 'Created in the last (days)', type: 'number', placeholder: '30', value: '30' },
        {
          id: 'type', label: 'Account type', type: 'single', items: [
            { id: 'all', label: 'Members and guests', default: true },
            { id: 'Guest', label: 'Guests only' },
            { id: 'Member', label: 'Members only' }
          ]
        }
      ],
      build: sel => {
        const filters = ['createdDateTime ge $cut'];
        if (sel.type !== 'all') filters.push("userType eq '" + sel.type + "'");
        return [
          "$cut = (Get-Date).AddDays(-" + num(sel.days, 30) + ").ToString('yyyy-MM-ddTHH:mm:ssZ')",
          'Get-MgUser -Filter "' + filters.join(' and ') + '" -All -Property Id, UserPrincipalName, DisplayName, UserType, CreatedDateTime, ExternalUserState, CreationType, Mail |',
          '    Select-Object UserPrincipalName, DisplayName, UserType, CreatedDateTime, ExternalUserState, CreationType |',
          '    Sort-Object CreatedDateTime -Descending |',
          '    Format-Table -AutoSize'
        ].join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'entra-user-last-signin',
      t: 'Last sign-in per account',
      p: ['Entra ID', 'Identity'],
      d: 'Uses the sign-in activity property to show when each account was last used, interactively and non-interactively.',
      k: 'signinactivity lastsignindatetime lastnoninteractive stale dormant account usage report',
      req: 'Microsoft.Graph module with AuditLog.Read.All and User.Read.All.',
      more: [
        { id: 'user', label: 'User (empty for all)', type: 'text', placeholder: 'jdoe@contoso.com' },
        { id: 'flags', label: 'Filter', type: 'multi', items: [{ id: 'enabled', label: 'Enabled accounts only', default: true }] }
      ],
      build: sel => {
        const user = q(sel.user);
        const lines = [
          'Get-MgUser -All -Property Id, UserPrincipalName, AccountEnabled, SignInActivity' + (user ? " -Filter \"userPrincipalName eq '" + user + "'\"" : '') + ' |',
          "    Select-Object UserPrincipalName, AccountEnabled,",
          "        @{N='LastInteractive';E={$_.SignInActivity.LastSignInDateTime}},",
          "        @{N='LastNonInteractive';E={$_.SignInActivity.LastNonInteractiveSignInDateTime}} |"
        ];
        if (sel.flags.has('enabled')) lines.push('    Where-Object { $_.AccountEnabled } |');
        lines.push('    Sort-Object LastInteractive -Descending |');
        lines.push('    Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'entra-directory-audit',
      t: 'Entra directory audit log',
      p: ['Entra ID', 'Collection'],
      d: 'The directory audit stream from Graph, filtered per category, with who did what to which object.',
      k: 'get-mgauditlogdirectoryaudit directory audit category initiatedby target resources activity graph',
      req: GRAPH,
      more: [
        { id: 'days', label: 'Look back (days)', type: 'number', placeholder: '7', value: '7' },
        { id: 'user', label: 'Actor or target (optional)', type: 'text', placeholder: 'jdoe@contoso.com' },
        {
          id: 'category', label: 'Category', type: 'single', items: [
            { id: 'all', label: 'All categories', default: true },
            { id: 'UserManagement', label: 'User management' },
            { id: 'GroupManagement', label: 'Group management' },
            { id: 'ApplicationManagement', label: 'Application management' },
            { id: 'RoleManagement', label: 'Role management' },
            { id: 'Policy', label: 'Policy' }
          ]
        }
      ],
      build: sel => {
        const filters = ['activityDateTime ge $cut'];
        if (sel.category !== 'all') filters.push("category eq '" + sel.category + "'");
        const lines = [
          "$cut = (Get-Date).AddDays(-" + num(sel.days, 7) + ").ToString('yyyy-MM-ddTHH:mm:ssZ')",
          '$events = Get-MgAuditLogDirectoryAudit -Filter "' + filters.join(' and ') + '" -All',
          '$report = $events | Select-Object ActivityDateTime, ActivityDisplayName, Category, Result,',
          "    @{N='Actor';E={if ($_.InitiatedBy.User) { $_.InitiatedBy.User.UserPrincipalName } else { $_.InitiatedBy.App.DisplayName }}},",
          "    @{N='Target';E={($_.TargetResources | ForEach-Object { if ($_.DisplayName) { $_.DisplayName } else { $_.UserPrincipalName } }) -join ', '}},",
          "    @{N='Changes';E={($_.TargetResources.ModifiedProperties | ForEach-Object { $_.DisplayName }) -join ', '}}"
        ];
        const user = q(sel.user);
        if (user) lines.push("$report = $report | Where-Object { $_.Actor -like '*" + user + "*' -or $_.Target -like '*" + user + "*' }");
        lines.push('$report | Sort-Object ActivityDateTime -Descending | Format-Table -AutoSize');
        return lines.join('\n');
      }
    }
  );

  /* ------------------------------------- enterprise applications and OAuth */

  add(
    {
      kind: 'ual',
      id: 'app-consent-grants',
      t: 'Consent granted to an application',
      p: ['Applications', 'Phishing', 'Persistence'],
      d: 'The audit trail of illicit consent grants: who consented, to which app, and whether it was tenant wide admin consent.',
      k: 'consent to application illicit grant oauth phishing isadmincontent delegated permission app consent',
      days: 30,
      ops: ['Consent to application.', 'Add delegation entry.', 'Set delegation entry.', 'Add app role assignment grant to user.', 'Add OAuth2PermissionGrant.'],
      cols: [
        ['Application', "($data.ModifiedProperties | Where-Object { $_.Name -eq 'ServicePrincipal.DisplayName' }).NewValue", true],
        ['Actor', '$data.UserId', true],
        ['AdminConsent', "($data.ModifiedProperties | Where-Object { $_.Name -eq 'ConsentContext.IsAdminConsent' }).NewValue", true, 'True means the grant covers every user in the tenant.'],
        ['Permissions', "($data.ModifiedProperties | Where-Object { $_.Name -eq 'ConsentAction.Permissions' }).NewValue", true, 'The scopes the application was granted.']
      ]
    },
    {
      kind: 'ual',
      id: 'app-service-principal-added',
      t: 'New applications and service principals',
      p: ['Applications', 'Persistence'],
      d: 'Registration of a new app or service principal, the first half of an OAuth persistence chain.',
      k: 'add service principal add application registration new app persistence backdoor enterprise application',
      days: 30,
      ops: ['Add service principal.', 'Remove service principal.', 'Add application.', 'Update application.', 'Delete application.', 'Add owner to application.', 'Add owner to service principal.'],
      cols: [
        ['Application', '$data.Target[3].ID', true, 'Target entry that carries the display name.'],
        ['Actor', '$data.UserId', true],
        ['Details', "($data.ModifiedProperties | ForEach-Object { $_.Name }) -join ', '", true]
      ]
    },
    {
      kind: 'ual',
      id: 'app-credentials-added',
      t: 'Credentials added to an application',
      p: ['Applications', 'Persistence'],
      d: 'A new secret or certificate on an existing app is a quiet way to keep app-only access, and it is one of the highest value detections in the log.',
      k: 'add service principal credentials secret certificate keycredentials passwordcredentials persistence app-only backdoor',
      days: 90,
      ops: ['Add service principal credentials.', 'Remove service principal credentials.', 'Update application.', 'Update application - Certificates and secrets management.'],
      cols: [
        ['Application', '$data.Target[3].ID', true],
        ['Actor', '$data.UserId', true],
        ['KeyDetails', "($data.ModifiedProperties | Where-Object { $_.Name -like '*KeyDescription*' }).NewValue", true, 'Describes the key or secret that was added.']
      ]
    },
    {
      kind: 'ps',
      id: 'app-permission-grants',
      t: 'OAuth permission grants in the tenant',
      p: ['Applications', 'Phishing'],
      d: 'Exports every delegated grant with the consenting user and the scopes, the report the Microsoft consent playbook is built around.',
      k: 'get-mgoauth2permissiongrant delegated consent allprincipals scope mail.read files.read illicit grant export',
      req: 'Microsoft.Graph module with Application.Read.All and User.Read.All.',
      more: [
        {
          id: 'scope', label: 'Show', type: 'single', items: [
            { id: 'all', label: 'All grants', default: true },
            { id: 'tenant', label: 'Tenant wide grants (AllPrincipals) only' },
            { id: 'risky', label: 'Risky scopes only' }
          ]
        },
        { id: 'user', label: 'Consenting user (optional)', type: 'text', placeholder: 'jdoe@contoso.com' },
        {
          id: 'output', label: 'Output', type: 'single', items: [
            { id: 'table', label: 'Table (Format-Table)', default: true },
            { id: 'csv', label: 'CSV file (Export-Csv)' },
            { id: 'grid', label: 'Grid view (Out-GridView)' }
          ]
        }
      ],
      build: sel => {
        const lines = [
          "$risky = 'Mail.', 'MailboxSettings.', 'Contacts.', 'Files.', 'Notes.', 'People.', 'Directory.AccessAsUser.All', 'user_impersonation', 'Directory.ReadWrite.All', 'Application.ReadWrite.All'",
          '$grants = Get-MgOauth2PermissionGrant -All',
          '$report = $grants | ForEach-Object {',
          '    $sp = Get-MgServicePrincipal -ServicePrincipalId $_.ClientId -ErrorAction SilentlyContinue',
          '    $principal = if ($_.PrincipalId) { (Get-MgUser -UserId $_.PrincipalId -ErrorAction SilentlyContinue).UserPrincipalName }',
          '    [pscustomobject]@{',
          '        Application   = $sp.DisplayName',
          '        AppId         = $sp.AppId',
          '        Publisher     = $sp.PublisherName',
          '        ConsentType   = $_.ConsentType',
          '        ConsentedBy   = $principal',
          '        Scopes        = $_.Scope',
          '        ResourceId    = $_.ResourceId',
          '    }',
          '}'
        ];
        if (sel.scope === 'tenant') lines.push("$report = $report | Where-Object { $_.ConsentType -eq 'AllPrincipals' }");
        if (sel.scope === 'risky') lines.push('$report = $report | Where-Object { $scopes = $_.Scopes; $risky | Where-Object { $scopes -like "*$_*" } }');
        const user = q(sel.user);
        if (user) lines.push("$report = $report | Where-Object { $_.ConsentedBy -eq '" + user + "' }");
        if (sel.output === 'csv') lines.push('$report | Sort-Object Application | Export-Csv -Path .\\ConsentGrants.csv -NoTypeInformation -Encoding UTF8');
        else if (sel.output === 'grid') lines.push("$report | Sort-Object Application | Out-GridView -Title 'OAuth consent grants'");
        else lines.push('$report | Sort-Object Application | Format-Table -AutoSize -Wrap');
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'app-role-assignments',
      t: 'Application permissions (app roles)',
      p: ['Applications', 'Privilege escalation'],
      d: 'Application permissions run without a user and cannot be revoked by a password reset, so this inventory is where quiet tenant wide access hides.',
      k: 'approleassignment application permission mail.readwrite directory.readwrite app-only daemon graph permission audit',
      req: 'Microsoft.Graph module with Application.Read.All and AppRoleAssignment.ReadWrite.All to remediate.',
      more: [
        { id: 'app', label: 'Application name (optional)', type: 'text', placeholder: 'Contoso Sync' },
        { id: 'flags', label: 'Filter', type: 'multi', items: [{ id: 'risky', label: 'High impact permissions only', default: true }] },
        {
          id: 'output', label: 'Output', type: 'single', items: [
            { id: 'table', label: 'Table (Format-Table)', default: true },
            { id: 'csv', label: 'CSV file (Export-Csv)' }
          ]
        }
      ],
      build: sel => {
        const app = q(sel.app);
        const lines = [
          "$graph = Get-MgServicePrincipal -Filter \"appId eq '00000003-0000-0000-c000-000000000000'\"",
          '$appRoles = @{}',
          '$graph.AppRoles | ForEach-Object { $appRoles[$_.Id] = $_.Value }',
          '$report = Get-MgServicePrincipal -All | ForEach-Object {',
          '    $sp = $_',
          '    Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue | ForEach-Object {',
          '        [pscustomobject]@{',
          '            Application = $sp.DisplayName',
          '            AppId       = $sp.AppId',
          '            Publisher   = $sp.PublisherName',
          '            Permission  = $appRoles[$_.AppRoleId]',
          '            Resource    = $_.ResourceDisplayName',
          '            Granted     = $_.CreatedDateTime',
          '        }',
          '    }',
          '}'
        ];
        if (app) lines.push("$report = $report | Where-Object { $_.Application -like '*" + app + "*' }");
        if (sel.flags.has('risky')) lines.push("$report = $report | Where-Object { $_.Permission -match 'ReadWrite.All|Mail.Read|Mail.Send|Files.Read.All|Directory.Read.All|RoleManagement|User.ManageCreds' }");
        if (sel.output === 'csv') lines.push('$report | Sort-Object Application | Export-Csv -Path .\\AppPermissions.csv -NoTypeInformation -Encoding UTF8');
        else lines.push('$report | Sort-Object Application, Permission | Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'app-inventory',
      t: 'Enterprise application inventory',
      p: ['Applications', 'Collection'],
      d: 'Every service principal with its publisher, verification status, owners and creation date, so new or unverified apps stand out.',
      k: 'get-mgserviceprincipal enterprise applications inventory publisher verified owners created reply url',
      req: GRAPH,
      more: [
        { id: 'days', label: 'Created in the last (days), empty for all', type: 'number', placeholder: '30' },
        {
          id: 'flags', label: 'Filter', type: 'multi', items: [
            { id: 'thirdParty', label: 'Hide Microsoft applications', default: true },
            { id: 'unverified', label: 'Unverified publishers only' }
          ]
        },
        { id: 'extra', label: 'Include', type: 'multi', items: [{ id: 'owners', label: 'Application owners', default: true }, { id: 'urls', label: 'Reply URLs' }] }
      ],
      build: sel => {
        const lines = ['$apps = Get-MgServicePrincipal -All'];
        if (sel.flags.has('thirdParty')) lines.push("$apps = $apps | Where-Object { $_.AppOwnerOrganizationId -ne 'f8cdef31-a31e-4b4a-93e4-5f571e91255a' -and $_.PublisherName -notlike 'Microsoft*' }");
        if (sel.flags.has('unverified')) lines.push('$apps = $apps | Where-Object { -not $_.VerifiedPublisher.DisplayName }');
        if (sel.days) {
          lines.push('$cut = (Get-Date).AddDays(-' + num(sel.days, 30) + ')');
          lines.push('$apps = $apps | Where-Object { $_.AdditionalProperties.createdDateTime -and [datetime]$_.AdditionalProperties.createdDateTime -ge $cut }');
        }
        lines.push('$report = $apps | ForEach-Object {');
        lines.push('    $row = [ordered]@{');
        lines.push('        Application = $_.DisplayName');
        lines.push('        AppId       = $_.AppId');
        lines.push('        Publisher   = $_.PublisherName');
        lines.push('        Verified    = $_.VerifiedPublisher.DisplayName');
        lines.push('        Enabled     = $_.AccountEnabled');
        lines.push('        Created     = $_.AdditionalProperties.createdDateTime');
        lines.push('    }');
        if (sel.extra.has('owners')) lines.push("    $row.Owners = ((Get-MgServicePrincipalOwner -ServicePrincipalId $_.Id -ErrorAction SilentlyContinue).AdditionalProperties.userPrincipalName) -join ', '");
        if (sel.extra.has('urls')) lines.push("    $row.ReplyUrls = $_.ReplyUrls -join ', '");
        lines.push('    [pscustomobject]$row');
        lines.push('}');
        lines.push('$report | Sort-Object Created -Descending | Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'app-registration-secrets',
      t: 'Application secrets and certificates',
      p: ['Applications', 'Persistence'],
      d: 'Lists the credentials on every app registration with the dates, so a secret added during the incident window is obvious.',
      k: 'passwordcredentials keycredentials secret certificate expiry added recently app registration persistence',
      req: 'Microsoft.Graph module with Application.Read.All.',
      more: [
        { id: 'days', label: 'Added in the last (days), empty for all', type: 'number', placeholder: '30' },
        { id: 'flags', label: 'Include', type: 'multi', items: [{ id: 'secrets', label: 'Client secrets', default: true }, { id: 'certs', label: 'Certificates', default: true }] }
      ],
      build: sel => {
        const lines = ['$report = Get-MgApplication -All | ForEach-Object {', '    $app = $_'];
        if (sel.flags.has('secrets')) {
          lines.push('    $app.PasswordCredentials | ForEach-Object {');
          lines.push("        [pscustomobject]@{ Application = $app.DisplayName; AppId = $app.AppId; Type = 'Secret'; Name = $_.DisplayName; Added = $_.StartDateTime; Expires = $_.EndDateTime }");
          lines.push('    }');
        }
        if (sel.flags.has('certs')) {
          lines.push('    $app.KeyCredentials | ForEach-Object {');
          lines.push("        [pscustomobject]@{ Application = $app.DisplayName; AppId = $app.AppId; Type = 'Certificate'; Name = $_.DisplayName; Added = $_.StartDateTime; Expires = $_.EndDateTime }");
          lines.push('    }');
        }
        lines.push('}');
        if (sel.days) {
          lines.push('$cut = (Get-Date).AddDays(-' + num(sel.days, 30) + ')');
          lines.push('$report = $report | Where-Object { $_.Added -ge $cut }');
        }
        lines.push('$report | Sort-Object Added -Descending | Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'app-consent-settings',
      t: 'User consent settings for the tenant',
      p: ['Applications', 'Hardening'],
      d: 'Shows whether ordinary users may still consent to applications, the setting that decides how far a consent phish gets.',
      k: 'authorizationpolicy defaultuserrolepermissions permissiongrantpolicy user consent admin consent workflow restrict',
      req: 'Microsoft.Graph module with Policy.Read.All.',
      more: [
        {
          id: 'checks', label: 'Show', type: 'multi', items: [
            { id: 'consent', label: 'User consent permissions', default: true },
            { id: 'policies', label: 'Permission grant policies', default: true },
            { id: 'requests', label: 'Pending admin consent requests' },
            { id: 'appreg', label: 'Can users register applications', default: true }
          ]
        }
      ],
      build: sel => {
        const lines = [];
        if (sel.checks.has('consent') || sel.checks.has('appreg')) {
          lines.push('$policy = Get-MgPolicyAuthorizationPolicy');
          lines.push('$policy | Format-List DisplayName, AllowedToUseSspr, AllowEmailVerifiedUsersToJoinOrganization, BlockMsolPowerShell');
          lines.push('$policy.DefaultUserRolePermissions | Format-List AllowedToCreateApps, AllowedToCreateSecurityGroups, AllowedToReadOtherUsers, PermissionGrantPoliciesAssigned');
        }
        if (sel.checks.has('policies')) {
          lines.push('Get-MgPolicyPermissionGrantPolicy -All | Select-Object Id, DisplayName, Description | Format-Table -AutoSize');
        }
        if (sel.checks.has('requests')) {
          lines.push('Get-MgIdentityGovernanceAppConsentRequest -All | Select-Object AppDisplayName, AppId, ConsentType, Status | Format-Table -AutoSize');
        }
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'app-disable-and-revoke',
      t: 'Disable an application and revoke its grants',
      p: ['Applications', 'Containment'],
      d: 'Containment for a malicious app: disable sign-in, delete the delegated grants and app role assignments, then revoke the users tokens.',
      k: 'disable service principal remove oauth2permissiongrant revoke containment malicious app remediate illicit consent',
      req: 'Microsoft.Graph module with Application.ReadWrite.All, DelegatedPermissionGrant.ReadWrite.All and Directory.AccessAsUser.All.',
      more: [
        { id: 'app', label: 'Application (display name or AppId)', type: 'text', placeholder: 'Suspicious App' },
        {
          id: 'steps', label: 'Steps', type: 'multi', items: [
            { id: 'show', label: 'Show what would be removed first', default: true },
            { id: 'disable', label: 'Disable sign-in for the app', default: true },
            { id: 'grants', label: 'Delete delegated permission grants', default: true },
            { id: 'roles', label: 'Delete application role assignments', default: true },
            { id: 'delete', label: 'Delete the service principal' }
          ]
        }
      ],
      build: sel => {
        const app = q(sel.app) || 'Suspicious App';
        const lines = ["$sp = Get-MgServicePrincipal -Filter \"displayName eq '" + app + "'\""];
        if (sel.steps.has('show')) {
          lines.push('$sp | Format-List DisplayName, AppId, Id, AccountEnabled, PublisherName');
          lines.push('Get-MgOauth2PermissionGrant -Filter "clientId eq \'$($sp.Id)\'" | Format-Table ConsentType, PrincipalId, Scope -AutoSize');
        }
        if (sel.steps.has('disable')) lines.push('Update-MgServicePrincipal -ServicePrincipalId $sp.Id -AccountEnabled:$false');
        if (sel.steps.has('grants')) {
          lines.push('Get-MgOauth2PermissionGrant -Filter "clientId eq \'$($sp.Id)\'" | ForEach-Object {');
          lines.push('    Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId $_.Id');
          lines.push('}');
        }
        if (sel.steps.has('roles')) {
          lines.push('Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id | ForEach-Object {');
          lines.push('    Remove-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -AppRoleAssignmentId $_.Id');
          lines.push('}');
        }
        if (sel.steps.has('delete')) lines.push('Remove-MgServicePrincipal -ServicePrincipalId $sp.Id');
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'app-users-with-app-access',
      t: 'Which users granted an app access',
      p: ['Applications', 'Phishing'],
      d: 'Turns one malicious application into the list of accounts that consented to it, which is the scoping step of a consent phishing case.',
      k: 'scope victims consented users per application principalid delegated grant blast radius',
      req: GRAPH,
      more: [
        { id: 'app', label: 'Application (display name)', type: 'text', placeholder: 'Suspicious App' },
        { id: 'flags', label: 'Also', type: 'multi', items: [{ id: 'signins', label: 'Show recent sign-ins to the app' }] }
      ],
      build: sel => {
        const app = q(sel.app) || 'Suspicious App';
        const lines = [
          "$sp = Get-MgServicePrincipal -Filter \"displayName eq '" + app + "'\"",
          'Get-MgOauth2PermissionGrant -Filter "clientId eq \'$($sp.Id)\'" | ForEach-Object {',
          '    [pscustomobject]@{',
          '        ConsentType = $_.ConsentType',
          '        User        = if ($_.PrincipalId) { (Get-MgUser -UserId $_.PrincipalId).UserPrincipalName } else { \'(all users)\' }',
          '        Scopes      = $_.Scope',
          '    }',
          '} | Format-Table -AutoSize -Wrap'
        ];
        if (sel.flags.has('signins')) {
          lines.push('Get-MgAuditLogSignIn -Filter "appId eq \'$($sp.AppId)\'" -Top 100 |');
          lines.push('    Select-Object CreatedDateTime, UserPrincipalName, IPAddress, ClientAppUsed |');
          lines.push('    Format-Table -AutoSize');
        }
        return lines.join('\n');
      }
    },
    {
      kind: 'ual',
      id: 'app-management-activity',
      t: 'All application management activity',
      p: ['Applications', 'Collection'],
      d: 'One search covering every application and service principal operation in the audit log, for the application section of a timeline.',
      k: 'application management delegation entry owner service principal audit all app changes',
      days: 30,
      ops: ['Add service principal.', 'Add service principal credentials.', 'Remove service principal.', 'Remove service principal credentials.',
        'Add delegation entry.', 'Set delegation entry.', 'Remove delegation entry.', 'Consent to application.',
        'Add owner to application.', 'Add owner to service principal.', 'Update application.', 'Add application.', 'Delete application.'],
      cols: [
        ['Target', '$data.Target[3].ID', true],
        ['Actor', '$data.UserId', true],
        ['Changed', "($data.ModifiedProperties | ForEach-Object { $_.Name }) -join ', '", true]
      ]
    }
  );

  /* ------------------------------------------- Exchange Online and mailboxes */

  add(
    {
      kind: 'ps',
      id: 'exo-inbox-rules-all',
      t: 'Inbox rules for every mailbox',
      p: ['Exchange Online', 'Persistence'],
      d: 'Dumps the client side rules of one mailbox or the whole tenant, with the actions that matter: forward, redirect, delete and move.',
      k: 'get-inboxrule client rules forward redirect delete move to folder hidden rule bec mailbox',
      more: [
        { id: 'user', label: 'Mailbox (empty for all)', type: 'text', placeholder: 'jdoe@contoso.com' },
        {
          id: 'cols', label: 'Columns', type: 'multi', wide: true, items: [
            { id: 'Name', label: 'Name', default: true },
            { id: 'Enabled', label: 'Enabled', default: true },
            { id: 'Priority', label: 'Priority' },
            { id: 'ForwardTo', label: 'ForwardTo', default: true },
            { id: 'ForwardAsAttachmentTo', label: 'ForwardAsAttachmentTo', default: true },
            { id: 'RedirectTo', label: 'RedirectTo', default: true },
            { id: 'DeleteMessage', label: 'DeleteMessage', default: true },
            { id: 'MoveToFolder', label: 'MoveToFolder', default: true },
            { id: 'MarkAsRead', label: 'MarkAsRead' },
            { id: 'StopProcessingRules', label: 'StopProcessingRules' },
            { id: 'From', label: 'From' },
            { id: 'SubjectContainsWords', label: 'SubjectContainsWords' },
            { id: 'BodyContainsWords', label: 'BodyContainsWords' },
            { id: 'Description', label: 'Description' }
          ]
        },
        {
          id: 'output', label: 'Output', type: 'single', items: [
            { id: 'table', label: 'Table (Format-Table)', default: true },
            { id: 'list', label: 'List (Format-List)' },
            { id: 'csv', label: 'CSV file (Export-Csv)' },
            { id: 'grid', label: 'Grid view (Out-GridView)' }
          ]
        }
      ],
      build: sel => {
        const user = q(sel.user);
        const cols = Array.from(sel.cols);
        const picked = (cols.length ? cols : ['Name', 'Enabled']).join(', ');
        const lines = [];
        if (user) {
          lines.push("$report = Get-InboxRule -Mailbox '" + user + "' |");
          lines.push("    Select-Object @{N='Mailbox';E={'" + user + "'}}, " + picked);
        } else {
          lines.push('$report = Get-Mailbox -ResultSize Unlimited | ForEach-Object {');
          lines.push('    $mailbox = $_.UserPrincipalName');
          lines.push('    Get-InboxRule -Mailbox $mailbox -ErrorAction SilentlyContinue |');
          lines.push("        Select-Object @{N='Mailbox';E={$mailbox}}, " + picked);
          lines.push('}');
        }
        if (sel.output === 'csv') lines.push('$report | Export-Csv -Path .\\InboxRules.csv -NoTypeInformation -Encoding UTF8');
        else if (sel.output === 'grid') lines.push("$report | Out-GridView -Title 'Inbox rules'");
        else if (sel.output === 'list') lines.push('$report | Format-List');
        else lines.push('$report | Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'exo-inbox-rules-suspicious',
      t: 'Suspicious inbox rules',
      p: ['Exchange Online', 'Persistence', 'Phishing'],
      d: 'Keeps only the rules that look like business email compromise: external forwarding, delete on arrival, or hiding mail in RSS and Archive folders.',
      k: 'malicious rule forward external delete rss subscriptions conversation history hide invoice payment keyword bec',
      more: [
        { id: 'user', label: 'Mailbox (empty for all)', type: 'text', placeholder: 'jdoe@contoso.com' },
        {
          id: 'checks', label: 'Flag rules that', type: 'multi', wide: true, items: [
            { id: 'forward', label: 'Forward or redirect anywhere', default: true },
            { id: 'external', label: 'Forward outside your domains', default: true },
            { id: 'delete', label: 'Delete messages', default: true },
            { id: 'hide', label: 'Move mail to a hiding folder (RSS, Archive, Notes)', default: true },
            { id: 'keywords', label: 'Match finance keywords in subject or body', default: true },
            { id: 'markRead', label: 'Mark messages as read' }
          ]
        },
        { id: 'domains', label: 'Internal domains (comma separated)', type: 'text', placeholder: 'contoso.com, contoso.be' }
      ],
      build: sel => {
        const user = q(sel.user);
        const domains = q(sel.domains) || 'contoso.com';
        const tests = [];
        if (sel.checks.has('forward')) tests.push('$_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo');
        if (sel.checks.has('external')) tests.push('($_.ForwardTo + $_.RedirectTo + $_.ForwardAsAttachmentTo | Where-Object { $_ -and ($internal | Where-Object { $addresses -notmatch $_ }) })');
        if (sel.checks.has('delete')) tests.push('$_.DeleteMessage');
        if (sel.checks.has('hide')) tests.push("$_.MoveToFolder -match 'RSS|Archive|Notes|Conversation History|Junk|Deleted'");
        if (sel.checks.has('keywords')) tests.push('($_.SubjectContainsWords + $_.BodyContainsWords) -match $keywords');
        if (sel.checks.has('markRead')) tests.push('$_.MarkAsRead');
        const lines = [
          "$internal = '" + domains + "' -split ',' | ForEach-Object { $_.Trim() }",
          "$keywords = 'invoice|payment|bank|iban|wire|swift|password|urgent|ceo|salaris|factuur'",
          '$mailboxes = Get-Mailbox ' + (user ? "-Identity '" + user + "'" : '-ResultSize Unlimited'),
          '$report = foreach ($mailbox in $mailboxes) {',
          '    Get-InboxRule -Mailbox $mailbox.UserPrincipalName -ErrorAction SilentlyContinue | ForEach-Object {',
          '        $addresses = ($_.ForwardTo + $_.RedirectTo + $_.ForwardAsAttachmentTo) -join \' \'',
          '        $flags = @()'
        ];
        if (sel.checks.has('forward')) lines.push("        if ($_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo) { $flags += 'Forwards' }");
        if (sel.checks.has('external')) lines.push("        if ($addresses -and -not ($internal | Where-Object { $addresses -like \"*$_*\" })) { $flags += 'External' }");
        if (sel.checks.has('delete')) lines.push("        if ($_.DeleteMessage) { $flags += 'Deletes' }");
        if (sel.checks.has('hide')) lines.push("        if ($_.MoveToFolder -match 'RSS|Archive|Notes|Conversation History|Junk|Deleted') { $flags += 'Hides' }");
        if (sel.checks.has('keywords')) lines.push("        if (($_.SubjectContainsWords + $_.BodyContainsWords) -match $keywords) { $flags += 'Keywords' }");
        if (sel.checks.has('markRead')) lines.push("        if ($_.MarkAsRead) { $flags += 'MarksRead' }");
        lines.push('        if ($flags) {');
        lines.push('            [pscustomobject]@{');
        lines.push('                Mailbox     = $mailbox.UserPrincipalName');
        lines.push('                Rule        = $_.Name');
        lines.push('                Enabled     = $_.Enabled');
        lines.push("                Flags       = $flags -join ', '");
        lines.push('                Destination = $addresses');
        lines.push('                MoveToFolder = $_.MoveToFolder');
        lines.push('                Description = ($_.Description -replace \"`r`n\", \" \")');
        lines.push('            }');
        lines.push('        }');
        lines.push('    }');
        lines.push('}');
        lines.push('$report | Format-Table -AutoSize -Wrap');
        return lines.join('\n');
      }
    },
    {
      kind: 'ual',
      id: 'exo-inbox-rule-changes',
      t: 'Inbox rule creation and changes',
      p: ['Exchange Online', 'Persistence'],
      d: 'The audit record of rules being created or edited, including the ones already deleted, with the client and IP address that did it.',
      k: 'new-inboxrule set-inboxrule updateinboxrules removed rule created modified outlook web client bec forwarding',
      days: 30,
      ops: ['New-InboxRule', 'Set-InboxRule', 'UpdateInboxRules', 'Remove-InboxRule', 'Disable-InboxRule', 'Enable-InboxRule'],
      cols: [
        ['Mailbox', '$data.MailboxOwnerUPN', true],
        ['RuleName', "($data.Parameters | Where-Object { $_.Name -eq 'Name' }).Value", true],
        ['Parameters', "($data.Parameters | ForEach-Object { $_.Name + '=' + $_.Value }) -join ' | '", true, 'Full parameter set of the cmdlet, this is where ForwardTo shows up.'],
        ['RuleOperations', "($data.OperationProperties | ForEach-Object { $_.Name + '=' + $_.Value }) -join ' | '", false, 'Used by UpdateInboxRules from the Outlook desktop client.']
      ]
    },
    {
      kind: 'ps',
      id: 'exo-forwarding-config',
      t: 'Mailbox forwarding settings',
      p: ['Exchange Online', 'Exfiltration'],
      d: 'Server side forwarding survives a password reset and is invisible to the user, so check it on every compromised mailbox.',
      k: 'forwardingsmtpaddress forwardingaddress delivertomailboxandforward external forward exfiltration hidden',
      more: [
        { id: 'user', label: 'Mailbox (empty for all)', type: 'text', placeholder: 'jdoe@contoso.com' },
        {
          id: 'flags', label: 'Filter', type: 'multi', items: [
            { id: 'set', label: 'Only mailboxes with forwarding set', default: true },
            { id: 'external', label: 'Only forwarding to external addresses' }
          ]
        },
        {
          id: 'extra', label: 'Also check', type: 'multi', items: [
            { id: 'remote', label: 'Remote domains that allow auto forwarding', default: true },
            { id: 'outbound', label: 'Outbound spam policy auto forwarding mode', default: true }
          ]
        }
      ],
      build: sel => {
        const user = q(sel.user);
        const lines = [
          '$report = Get-Mailbox ' + (user ? "-Identity '" + user + "'" : '-ResultSize Unlimited') + ' |',
          '    Select-Object UserPrincipalName, ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward'
        ];
        if (sel.flags.has('set')) lines.push('$report = $report | Where-Object { $_.ForwardingAddress -or $_.ForwardingSmtpAddress }');
        if (sel.flags.has('external')) {
          lines.push('$domains = (Get-AcceptedDomain).DomainName');
          lines.push('$report = $report | Where-Object { $address = $_.ForwardingSmtpAddress; $address -and -not ($domains | Where-Object { $address -like "*$_*" }) }');
        }
        lines.push('$report | Format-Table -AutoSize');
        if (sel.extra.has('remote')) lines.push('Get-RemoteDomain | Select-Object Name, DomainName, AutoForwardEnabled | Format-Table -AutoSize');
        if (sel.extra.has('outbound')) lines.push('Get-HostedOutboundSpamFilterPolicy | Select-Object Name, AutoForwardingMode | Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      kind: 'ual',
      id: 'exo-mailbox-config-changes',
      t: 'Mailbox configuration changes',
      p: ['Exchange Online', 'Persistence'],
      d: 'Admin side changes to a mailbox: forwarding, delegation, retention and audit settings, each with the full parameter list.',
      k: 'set-mailbox exchangeadmin forwarding delegate audit configuration change cmdlet parameters',
      days: 30, rec: 'ExchangeAdmin',
      ops: ['Set-Mailbox', 'Set-CASMailbox', 'Add-MailboxPermission', 'Remove-MailboxPermission', 'Add-RecipientPermission', 'Set-MailboxAutoReplyConfiguration', 'Set-MailboxFolderPermission', 'Add-MailboxFolderPermission'],
      cols: [
        ['Target', '$data.ObjectId', true],
        ['Cmdlet', '$data.Operation', true],
        ['Parameters', "($data.Parameters | ForEach-Object { $_.Name + '=' + $_.Value }) -join ' | '", true]
      ]
    },
    {
      kind: 'ps',
      id: 'exo-out-of-office',
      t: 'Out of office replies',
      p: ['Exchange Online', 'Phishing'],
      d: 'Reads the automatic reply state and both message bodies, since attackers use auto replies to answer their own phishing threads.',
      k: 'get-mailboxautoreplyconfiguration out of office oof automatic reply internal external message changed autoreply',
      more: [
        { id: 'user', label: 'Mailbox (empty for all)', type: 'text', placeholder: 'jdoe@contoso.com' },
        {
          id: 'flags', label: 'Filter', type: 'multi', items: [
            { id: 'enabled', label: 'Only mailboxes with auto reply enabled', default: true },
            { id: 'links', label: 'Only replies that contain a link or an address' }
          ]
        },
        {
          id: 'output', label: 'Output', type: 'single', items: [
            { id: 'table', label: 'Table (Format-Table)', default: true },
            { id: 'list', label: 'List with the full message text' },
            { id: 'csv', label: 'CSV file (Export-Csv)' }
          ]
        }
      ],
      build: sel => {
        const user = q(sel.user);
        const lines = [
          '$mailboxes = Get-Mailbox ' + (user ? "-Identity '" + user + "'" : '-ResultSize Unlimited'),
          '$report = foreach ($mailbox in $mailboxes) {',
          '    $oof = Get-MailboxAutoReplyConfiguration -Identity $mailbox.UserPrincipalName -ErrorAction SilentlyContinue',
          '    [pscustomobject]@{',
          '        Mailbox         = $mailbox.UserPrincipalName',
          '        State           = $oof.AutoReplyState',
          '        Start           = $oof.StartTime',
          '        End             = $oof.EndTime',
          '        ExternalAudience = $oof.ExternalAudience',
          "        InternalMessage = ($oof.InternalMessage -replace '<[^>]+>', ' ' -replace '\\s+', ' ').Trim()",
          "        ExternalMessage = ($oof.ExternalMessage -replace '<[^>]+>', ' ' -replace '\\s+', ' ').Trim()",
          '    }',
          '}'
        ];
        if (sel.flags.has('enabled')) lines.push("$report = $report | Where-Object { $_.State -ne 'Disabled' }");
        if (sel.flags.has('links')) lines.push("$report = $report | Where-Object { $_.InternalMessage -match 'http|@' -or $_.ExternalMessage -match 'http|@' }");
        if (sel.output === 'csv') lines.push('$report | Export-Csv -Path .\\OutOfOffice.csv -NoTypeInformation -Encoding UTF8');
        else if (sel.output === 'list') lines.push('$report | Format-List');
        else lines.push('$report | Format-Table Mailbox, State, Start, End, ExternalAudience -AutoSize');
        return lines.join('\n');
      }
    },
    {
      kind: 'ual',
      id: 'exo-out-of-office-changes',
      t: 'Out of office changes in the audit log',
      p: ['Exchange Online', 'Phishing'],
      d: 'Shows when an automatic reply was turned on or its text changed, with the message body that was set.',
      k: 'set-mailboxautoreplyconfiguration oof changed enabled internalmessage externalmessage audit auto reply',
      days: 30, rec: 'ExchangeAdmin',
      ops: ['Set-MailboxAutoReplyConfiguration'],
      cols: [
        ['Mailbox', '$data.ObjectId', true],
        ['NewState', "($data.Parameters | Where-Object { $_.Name -eq 'AutoReplyState' }).Value", true],
        ['InternalMessage', "($data.Parameters | Where-Object { $_.Name -eq 'InternalMessage' }).Value", true],
        ['ExternalMessage', "($data.Parameters | Where-Object { $_.Name -eq 'ExternalMessage' }).Value", true]
      ]
    },
    {
      kind: 'ps',
      id: 'exo-mailbox-permissions',
      t: 'Mailbox and delegate permissions',
      p: ['Exchange Online', 'Persistence'],
      d: 'Who else can open, send as, or send on behalf of a mailbox, with the inherited entries filtered out.',
      k: 'get-mailboxpermission fullaccess sendas sendonbehalf recipientpermission delegate access persistence',
      more: [
        { id: 'user', label: 'Mailbox (empty for all)', type: 'text', placeholder: 'jdoe@contoso.com' },
        {
          id: 'checks', label: 'Report', type: 'multi', items: [
            { id: 'full', label: 'FullAccess (Get-MailboxPermission)', default: true },
            { id: 'sendas', label: 'SendAs (Get-RecipientPermission)', default: true },
            { id: 'onbehalf', label: 'SendOnBehalf (GrantSendOnBehalfTo)', default: true }
          ]
        },
        { id: 'flags', label: 'Filter', type: 'multi', items: [{ id: 'skipSelf', label: 'Hide self and NT AUTHORITY entries', default: true }] }
      ],
      build: sel => {
        const user = q(sel.user);
        const target = user ? "-Identity '" + user + "'" : '-ResultSize Unlimited';
        const skip = sel.flags.has('skipSelf');
        const lines = ['$mailboxes = Get-Mailbox ' + target, '$report = foreach ($mailbox in $mailboxes) {'];
        if (sel.checks.has('full')) {
          lines.push('    Get-MailboxPermission -Identity $mailbox.UserPrincipalName |');
          lines.push('        Where-Object { -not $_.IsInherited' + (skip ? " -and $_.User -notlike 'NT AUTHORITY*' -and $_.User -ne $mailbox.UserPrincipalName" : '') + ' } |');
          lines.push("        Select-Object @{N='Mailbox';E={$mailbox.UserPrincipalName}}, @{N='Type';E={'FullAccess'}}, User, @{N='Rights';E={$_.AccessRights -join ', '}}");
        }
        if (sel.checks.has('sendas')) {
          lines.push('    Get-RecipientPermission -Identity $mailbox.UserPrincipalName |');
          lines.push('        Where-Object { $_.Trustee -notlike \'NT AUTHORITY*\' } |');
          lines.push("        Select-Object @{N='Mailbox';E={$mailbox.UserPrincipalName}}, @{N='Type';E={'SendAs'}}, @{N='User';E={$_.Trustee}}, @{N='Rights';E={$_.AccessRights -join ', '}}");
        }
        if (sel.checks.has('onbehalf')) {
          lines.push('    $mailbox.GrantSendOnBehalfTo | ForEach-Object {');
          lines.push("        [pscustomobject]@{ Mailbox = $mailbox.UserPrincipalName; Type = 'SendOnBehalf'; User = $_; Rights = 'SendOnBehalf' }");
          lines.push('    }');
        }
        lines.push('}');
        lines.push('$report | Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'exo-folder-permissions',
      t: 'Mailbox folder permissions',
      p: ['Exchange Online', 'Persistence'],
      d: 'Checks the folder level rights, including the Default and Anonymous entries that quietly expose a whole inbox or calendar.',
      k: 'get-mailboxfolderpermission default anonymous inbox calendar top of information store delegate folder rights',
      more: [
        { id: 'user', label: 'Mailbox', type: 'text', placeholder: 'jdoe@contoso.com' },
        {
          id: 'folders', label: 'Folders', type: 'multi', items: [
            { id: ':\\', label: 'Mailbox root', default: true },
            { id: ':\\Inbox', label: 'Inbox', default: true },
            { id: ':\\Calendar', label: 'Calendar', default: true },
            { id: ':\\Sent Items', label: 'Sent Items' },
            { id: ':\\Contacts', label: 'Contacts' }
          ]
        },
        { id: 'flags', label: 'Filter', type: 'multi', items: [{ id: 'notNone', label: 'Hide entries with no access', default: true }] }
      ],
      build: sel => {
        const user = q(sel.user) || 'jdoe@contoso.com';
        const folders = Array.from(sel.folders);
        const list = (folders.length ? folders : [':\\']).map(f => "'" + f + "'").join(', ');
        const lines = [
          "$mailbox = '" + user + "'",
          '$folders = ' + list,
          '$report = foreach ($folder in $folders) {',
          '    Get-MailboxFolderPermission -Identity "$mailbox$folder" -ErrorAction SilentlyContinue |',
          "        Select-Object @{N='Folder';E={$folder}}, User, @{N='Rights';E={$_.AccessRights -join ', '}}, SharingPermissionFlags",
          '}'
        ];
        if (sel.flags.has('notNone')) lines.push("$report = $report | Where-Object { $_.Rights -ne 'None' }");
        lines.push('$report | Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      kind: 'ual',
      id: 'exo-delegate-activity',
      t: 'Delegate and permission activity',
      p: ['Exchange Online', 'Persistence'],
      d: 'Folder permission and calendar delegation events from the mailbox audit stream, which is where mailbox sharing abuse appears.',
      k: 'addfolderpermissions modifyfolderpermissions updatecalendardelegation add-mailboxpermission delegate sharing',
      days: 30, rec: 'ExchangeItem',
      ops: ['Add-MailboxPermission', 'Remove-MailboxPermission', 'AddFolderPermissions', 'ModifyFolderPermissions', 'RemoveFolderPermissions', 'UpdateCalendarDelegation'],
      cols: [
        ['Mailbox', '$data.MailboxOwnerUPN', true],
        ['LogonType', '$data.LogonType', true, '0 owner, 1 admin, 2 delegate.'],
        ['Details', "($data.Item | ConvertTo-Json -Compress -Depth 4)", false],
        ['Parameters', "($data.Parameters | ForEach-Object { $_.Name + '=' + $_.Value }) -join ' | '", true]
      ]
    },
    {
      kind: 'ps',
      id: 'exo-mailbox-audit-config',
      t: 'Mailbox audit configuration for a user',
      p: ['Exchange Online', 'Collection'],
      d: 'Shows which owner, delegate and admin actions are actually being audited on a mailbox, and for how long they are kept.',
      k: 'auditenabled auditowner auditdelegate auditadmin auditlogagelimit mailbox auditing rules per user defaultauditset',
      more: [
        { id: 'user', label: 'Mailbox (empty for all)', type: 'text', placeholder: 'jdoe@contoso.com' },
        {
          id: 'extra', label: 'Also', type: 'multi', items: [
            { id: 'bypass', label: 'Check the audit bypass list', default: true },
            { id: 'recommend', label: 'Show the command that enables full auditing' }
          ]
        }
      ],
      build: sel => {
        const user = q(sel.user);
        const target = user ? "-Identity '" + user + "'" : '-ResultSize Unlimited';
        const lines = [
          'Get-Mailbox ' + target + ' |',
          '    Select-Object UserPrincipalName, AuditEnabled, AuditLogAgeLimit, DefaultAuditSet,',
          "        @{N='AuditOwner';E={$_.AuditOwner -join ', '}},",
          "        @{N='AuditDelegate';E={$_.AuditDelegate -join ', '}},",
          "        @{N='AuditAdmin';E={$_.AuditAdmin -join ', '}} |",
          '    Format-List'
        ];
        if (sel.extra.has('bypass')) {
          lines.push('Get-MailboxAuditBypassAssociation ' + (user ? "-Identity '" + user + "'" : '-ResultSize Unlimited') + ' |');
          lines.push('    Where-Object { $_.AuditBypassEnabled } |');
          lines.push('    Format-Table Name, AuditBypassEnabled -AutoSize');
        }
        if (sel.extra.has('recommend')) {
          lines.push('Set-Mailbox ' + (user ? "-Identity '" + user + "'" : '-Identity <mailbox>') + ' -AuditEnabled $true -AuditLogAgeLimit 180 `');
          lines.push('    -AuditOwner @{Add="MailItemsAccessed","Send","SoftDelete","HardDelete","Update","MoveToDeletedItems","UpdateInboxRules"}');
        }
        return lines.join('\n');
      }
    },
    {
      kind: 'ual',
      id: 'exo-mail-items-accessed',
      t: 'Which mail was actually read',
      p: ['Exchange Online', 'Exfiltration'],
      d: 'MailItemsAccessed is the record that answers "what did they read", with sync operations being far more serious than single binds.',
      k: 'mailitemsaccessed bind sync folders internetmessageid data breach scope read mail e5 advanced audit',
      days: 30, rec: 'ExchangeItemAggregated', ip: 1,
      cols: [
        ['Mailbox', '$data.MailboxOwnerUPN', true],
        ['AccessType', "$data.OperationProperties | Where-Object { $_.Name -eq 'MailAccessType' } | Select-Object -ExpandProperty Value", true, 'Sync means a whole folder was pulled down.'],
        ['Throttled', "$data.OperationProperties | Where-Object { $_.Name -eq 'IsThrottled' } | Select-Object -ExpandProperty Value", true, 'True means records were dropped, treat the mailbox as fully accessed.'],
        ['Folders', "($data.Folders | ForEach-Object { $_.Path }) -join ', '", true],
        ['MessageCount', "($data.Folders | ForEach-Object { $_.FolderItems.Count } | Measure-Object -Sum).Sum", true],
        ['MessageIds', "($data.Folders.FolderItems.InternetMessageId) -join ' '", false, 'Feed these into a content search to list the exact mails.']
      ]
    },
    {
      kind: 'ual',
      id: 'exo-messages-sent',
      t: 'Mail sent from a mailbox',
      p: ['Exchange Online', 'Phishing'],
      d: 'Send, SendAs and SendOnBehalf records, the fastest way to see the phishing wave that went out from a compromised account.',
      k: 'send sendas sendonbehalf outbound phishing wave sent items subject recipients internal spread',
      days: 14, rec: 'ExchangeItem',
      ops: ['Send', 'SendAs', 'SendOnBehalf'],
      cols: [
        ['Mailbox', '$data.MailboxOwnerUPN', true],
        ['Subject', '$data.Item.Subject', true],
        ['SentTo', "($data.Item.ToRecipients | ForEach-Object { $_ }) -join ', '", true],
        ['MessageId', '$data.Item.InternetMessageId', false],
        ['SendType', '$data.SendAsUserSmtp', false]
      ]
    },
    {
      kind: 'ual',
      id: 'exo-mail-deleted',
      t: 'Mail deleted or moved',
      p: ['Exchange Online', 'Anti-forensics'],
      d: 'Deletion and move records expose the clean-up an attacker does after sending mail from the mailbox.',
      k: 'harddelete softdelete movetodeleteditems move purge cover tracks anti forensics deleted items recoverable',
      days: 30, rec: 'ExchangeItem',
      ops: ['HardDelete', 'SoftDelete', 'MoveToDeletedItems', 'Move', 'Update'],
      cols: [
        ['Mailbox', '$data.MailboxOwnerUPN', true],
        ['Subject', "($data.AffectedItems | ForEach-Object { $_.Subject }) -join ' | '", true],
        ['Folder', '$data.Folder.Path', true],
        ['DestFolder', '$data.DestFolder.Path', true],
        ['LogonType', '$data.LogonType', false]
      ]
    },
    {
      kind: 'ual',
      id: 'exo-mailbox-searches',
      t: 'Searches run inside a mailbox',
      p: ['Exchange Online', 'Exfiltration'],
      d: 'SearchQueryInitiated shows the terms someone typed in Outlook, which often reads like an attacker shopping list.',
      k: 'searchqueryinitiated outlook search terms query keywords invoice password reconnaissance inside mailbox',
      days: 30, rec: 'ExchangeItem',
      ops: ['SearchQueryInitiated', 'SearchQueryInitiatedExchange'],
      cols: [
        ['Mailbox', '$data.MailboxOwnerUPN', true],
        ['Query', '$data.QueryText', true],
        ['Scope', '$data.QueryScope', true]
      ]
    },
    {
      kind: 'ual',
      id: 'exo-mailbox-logons',
      t: 'Mailbox logons and folder access',
      p: ['Exchange Online', 'Identity'],
      d: 'Owner, delegate and admin logons to a mailbox, useful when you suspect access through delegation rather than a stolen password.',
      k: 'mailboxlogin folderbind attachmentaccess logontype delegate owner admin access mailbox opened',
      days: 14, rec: 'ExchangeItem',
      ops: ['MailboxLogin', 'FolderBind', 'AttachmentAccess', 'MessageBind'],
      cols: [
        ['Mailbox', '$data.MailboxOwnerUPN', true],
        ['LogonUser', '$data.LogonUserSid', false],
        ['LogonType', '$data.LogonType', true, '0 owner, 1 admin, 2 delegate.'],
        ['Folder', '$data.Folder.Path', true]
      ]
    },
    {
      kind: 'ps',
      id: 'exo-legacy-protocols',
      t: 'Legacy protocols per mailbox',
      p: ['Exchange Online', 'Identity'],
      d: 'Which mailboxes still allow IMAP, POP, SMTP AUTH and ActiveSync, and the command to switch them off.',
      k: 'get-casmailbox imapenabled popenabled smtpclientauthenticationdisabled activesync legacy protocol basic auth disable',
      more: [
        { id: 'user', label: 'Mailbox (empty for all)', type: 'text', placeholder: 'jdoe@contoso.com' },
        { id: 'flags', label: 'Filter', type: 'multi', items: [{ id: 'enabled', label: 'Only mailboxes with a legacy protocol enabled', default: true }] },
        { id: 'extra', label: 'Also', type: 'multi', items: [{ id: 'org', label: 'Show the tenant wide SMTP AUTH setting', default: true }, { id: 'disable', label: 'Show the command that disables them' }] }
      ],
      build: sel => {
        const user = q(sel.user);
        const lines = [
          '$report = Get-CASMailbox ' + (user ? "-Identity '" + user + "'" : '-ResultSize Unlimited') + ' |',
          '    Select-Object PrimarySmtpAddress, ImapEnabled, PopEnabled, SmtpClientAuthenticationDisabled, ActiveSyncEnabled, OWAEnabled, MAPIEnabled'
        ];
        if (sel.flags.has('enabled')) lines.push('$report = $report | Where-Object { $_.ImapEnabled -or $_.PopEnabled -or $_.SmtpClientAuthenticationDisabled -eq $false }');
        lines.push('$report | Format-Table -AutoSize');
        if (sel.extra.has('org')) lines.push('Get-TransportConfig | Format-List SmtpClientAuthenticationDisabled');
        if (sel.extra.has('disable')) {
          lines.push('Set-CASMailbox ' + (user ? "-Identity '" + user + "'" : '-Identity <mailbox>') + ' -ImapEnabled $false -PopEnabled $false -SmtpClientAuthenticationDisabled $true');
        }
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'exo-message-trace',
      t: 'Message trace',
      p: ['Exchange Online', 'Phishing'],
      d: 'Traces mail in and out of the tenant by sender, recipient or subject, the first tool for "who else got this phish".',
      k: 'get-messagetracev2 message trace sender recipient subject delivered failed quarantine phishing wave 10 days',
      more: [
        { id: 'sender', label: 'Sender address (optional)', type: 'text', placeholder: 'jdoe@contoso.com' },
        { id: 'recipient', label: 'Recipient address (optional)', type: 'text', placeholder: 'victim@contoso.com' },
        { id: 'days', label: 'Look back (days)', type: 'number', placeholder: '7', value: '7', hint: 'Message trace keeps 10 days of detail online.' },
        { id: 'subject', label: 'Subject contains (optional)', type: 'text', placeholder: 'invoice' },
        {
          id: 'output', label: 'Output', type: 'single', items: [
            { id: 'table', label: 'Table (Format-Table)', default: true },
            { id: 'csv', label: 'CSV file (Export-Csv)' },
            { id: 'recipients', label: 'Count per recipient' },
            { id: 'status', label: 'Count per status' }
          ]
        }
      ],
      build: sel => {
        const args = ['-StartDate $start -EndDate $end'];
        if (q(sel.sender)) args.push("-SenderAddress '" + q(sel.sender) + "'");
        if (q(sel.recipient)) args.push("-RecipientAddress '" + q(sel.recipient) + "'");
        const lines = [
          '$start = (Get-Date).AddDays(-' + num(sel.days, 7) + ')',
          '$end = Get-Date',
          '$messages = Get-MessageTraceV2 ' + args.join(' ') + ' -ResultSize 5000'
        ];
        if (q(sel.subject)) lines.push("$messages = $messages | Where-Object { $_.Subject -like '*" + q(sel.subject) + "*' }");
        lines.push('$report = $messages | Select-Object Received, SenderAddress, RecipientAddress, Subject, Status, FromIP, ToIP, Size, MessageId');
        if (sel.output === 'csv') lines.push('$report | Export-Csv -Path .\\MessageTrace.csv -NoTypeInformation -Encoding UTF8');
        else if (sel.output === 'recipients') lines.push('$report | Group-Object RecipientAddress -NoElement | Sort-Object Count -Descending | Format-Table -AutoSize');
        else if (sel.output === 'status') lines.push('$report | Group-Object Status -NoElement | Sort-Object Count -Descending | Format-Table -AutoSize');
        else lines.push('$report | Sort-Object Received -Descending | Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'exo-transport-rules',
      t: 'Transport rules and connectors',
      p: ['Exchange Online', 'Persistence'],
      d: 'Tenant wide mail flow: a rule that blind copies an external address or a rogue inbound connector affects everyone, not one mailbox.',
      k: 'get-transportrule blindcopyto redirect connector inboundconnector outboundconnector mail flow tampering journaling',
      more: [
        {
          id: 'checks', label: 'Report', type: 'multi', items: [
            { id: 'rules', label: 'Transport rules', default: true },
            { id: 'suspicious', label: 'Only rules that copy or redirect mail', default: true },
            { id: 'connectors', label: 'Inbound and outbound connectors', default: true },
            { id: 'journal', label: 'Journal rules' },
            { id: 'changes', label: 'Recent rule changes from the audit log' }
          ]
        },
        { id: 'days', label: 'Look back (days) for changes', type: 'number', placeholder: '30', value: '30' }
      ],
      build: sel => {
        const lines = [];
        if (sel.checks.has('rules')) {
          lines.push('$rules = Get-TransportRule');
          if (sel.checks.has('suspicious')) lines.push('$rules = $rules | Where-Object { $_.BlindCopyTo -or $_.CopyTo -or $_.RedirectMessageTo -or $_.AddToRecipients }');
          lines.push('$rules | Select-Object Name, State, Priority, WhenChanged,');
          lines.push("    @{N='BlindCopyTo';E={$_.BlindCopyTo -join ', '}}, @{N='RedirectTo';E={$_.RedirectMessageTo -join ', '}},");
          lines.push("    @{N='CopyTo';E={$_.CopyTo -join ', '}} |");
          lines.push('    Format-Table -AutoSize');
        }
        if (sel.checks.has('connectors')) {
          lines.push('Get-InboundConnector | Select-Object Name, Enabled, SenderDomains, SenderIPAddresses, WhenChanged | Format-Table -AutoSize');
          lines.push('Get-OutboundConnector | Select-Object Name, Enabled, RecipientDomains, SmartHosts, WhenChanged | Format-Table -AutoSize');
        }
        if (sel.checks.has('journal')) lines.push('Get-JournalRule | Select-Object Name, Enabled, Recipient, JournalEmailAddress | Format-Table -AutoSize');
        if (sel.checks.has('changes')) {
          lines.push('$start = (Get-Date).AddDays(-' + num(sel.days, 30) + ')');
          lines.push('Search-UnifiedAuditLog -StartDate $start -EndDate (Get-Date) -RecordType ExchangeAdmin `');
          lines.push('    -Operations "New-TransportRule", "Set-TransportRule", "Remove-TransportRule", "New-InboundConnector", "Set-InboundConnector", "New-OutboundConnector" -ResultSize 5000 |');
          lines.push('    ForEach-Object {');
          lines.push('        $data = $_.AuditData | ConvertFrom-Json');
          lines.push("        [pscustomobject]@{ Time = $_.CreationDate; User = $_.UserIds; Operation = $_.Operations; Target = $data.ObjectId }");
          lines.push('    } | Format-Table -AutoSize');
        }
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'exo-mobile-devices',
      t: 'Mobile devices on a mailbox',
      p: ['Exchange Online', 'Persistence'],
      d: 'ActiveSync partnerships created during the incident window are a quiet way to keep a copy of the mailbox.',
      k: 'get-mobiledevice activesync partnership device sync state first sync time remove device exfiltration',
      more: [
        { id: 'user', label: 'Mailbox', type: 'text', placeholder: 'jdoe@contoso.com' },
        { id: 'days', label: 'Added in the last (days), empty for all', type: 'number', placeholder: '30' },
        { id: 'extra', label: 'Also', type: 'multi', items: [{ id: 'stats', label: 'Include last sync statistics', default: true }] }
      ],
      build: sel => {
        const user = q(sel.user) || 'jdoe@contoso.com';
        const lines = ["$devices = Get-MobileDevice -Mailbox '" + user + "'"];
        if (sel.days) {
          lines.push('$cut = (Get-Date).AddDays(-' + num(sel.days, 30) + ')');
          lines.push('$devices = $devices | Where-Object { $_.WhenCreated -ge $cut }');
        }
        if (sel.extra.has('stats')) {
          lines.push('$devices | ForEach-Object {');
          lines.push("    $stats = Get-MobileDeviceStatistics -Identity $_.Identity -ErrorAction SilentlyContinue");
          lines.push('    [pscustomobject]@{');
          lines.push('        Device      = $_.FriendlyName');
          lines.push('        Model       = $_.DeviceModel');
          lines.push('        OS          = $_.DeviceOS');
          lines.push('        UserAgent   = $_.DeviceUserAgent');
          lines.push('        Created     = $_.WhenCreated');
          lines.push('        FirstSync   = $stats.FirstSyncTime');
          lines.push('        LastSuccess = $stats.LastSuccessSync');
          lines.push('        State       = $_.DeviceAccessState');
          lines.push('    }');
          lines.push('} | Format-Table -AutoSize');
        } else {
          lines.push('$devices | Select-Object FriendlyName, DeviceModel, DeviceOS, DeviceUserAgent, WhenCreated, DeviceAccessState | Format-Table -AutoSize');
        }
        return lines.join('\n');
      }
    },
    {
      kind: 'ual',
      id: 'exo-admin-cmdlets',
      t: 'Exchange admin cmdlets that were run',
      p: ['Exchange Online', 'Collection'],
      d: 'Every Exchange admin cmdlet in the window with its parameters, which catches tenant level tampering you did not think to look for.',
      k: 'exchangeadmin cmdlet parameters admin activity new-transportrule set-organizationconfig audit everything',
      days: 14, rec: 'ExchangeAdmin',
      cols: [
        ['Cmdlet', '$data.Operation', true],
        ['Target', '$data.ObjectId', true],
        ['Parameters', "($data.Parameters | ForEach-Object { $_.Name + '=' + $_.Value }) -join ' | '", true],
        ['ClientApp', '$data.ClientAppId', false]
      ]
    },
    {
      kind: 'ps',
      id: 'exo-compliance-search',
      t: 'Content search for phishing mail',
      p: ['Purview', 'Containment'],
      d: 'Builds a content search across all mailboxes for the phishing message, then previews the hits before anything is removed.',
      k: 'new-compliancesearch kql subject from attachment preview statistics hunt phishing mail search purview',
      req: 'Security and Compliance PowerShell (Connect-IPPSSession) with eDiscovery Manager rights.',
      more: [
        { id: 'name', label: 'Search name', type: 'text', placeholder: 'IR-phish-2026-09' },
        { id: 'sender', label: 'Sender address', type: 'text', placeholder: 'attacker@evil.example' },
        { id: 'subject', label: 'Subject contains', type: 'text', placeholder: 'Invoice overdue' },
        { id: 'days', label: 'Sent in the last (days)', type: 'number', placeholder: '14', value: '14' },
        {
          id: 'steps', label: 'Steps', type: 'multi', items: [
            { id: 'create', label: 'Create and start the search', default: true },
            { id: 'stats', label: 'Show the hit count per mailbox', default: true },
            { id: 'preview', label: 'Preview the matching items' }
          ]
        }
      ],
      build: sel => {
        const name = q(sel.name) || 'IR-search';
        const parts = [];
        if (q(sel.sender)) parts.push('from:' + q(sel.sender));
        if (q(sel.subject)) parts.push('subject:"' + q(sel.subject) + '"');
        parts.push('sent>=' + '$cut');
        const lines = [
          "$cut = (Get-Date).AddDays(-" + num(sel.days, 14) + ").ToString('yyyy-MM-dd')",
          '$query = \'' + parts.join(' AND ').replace('$cut', "' + $cut + '") + '\''
        ];
        if (sel.steps.has('create')) {
          lines.push("New-ComplianceSearch -Name '" + name + "' -ExchangeLocation All -ContentMatchQuery $query");
          lines.push("Start-ComplianceSearch -Identity '" + name + "'");
        }
        if (sel.steps.has('stats')) {
          lines.push("do { Start-Sleep -Seconds 15; $search = Get-ComplianceSearch -Identity '" + name + "' } while ($search.Status -ne 'Completed')");
          lines.push('$search | Format-List Name, Status, Items, Size');
          lines.push('$search.SearchStatistics | ConvertFrom-Json | Select-Object -ExpandProperty ExchangeBinding');
        }
        if (sel.steps.has('preview')) {
          lines.push("New-ComplianceSearchAction -SearchName '" + name + "' -Preview");
          lines.push("Get-ComplianceSearchAction -Identity '" + name + "_Preview' | Format-List Name, Status, Results");
        }
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'exo-purge-messages',
      t: 'Purge a phishing message from all mailboxes',
      p: ['Purview', 'Containment'],
      d: 'Soft or hard deletes the results of a content search, the standard way to pull a phishing wave back out of the tenant.',
      k: 'new-compliancesearchaction purge softdelete harddelete remove phishing mail from all mailboxes containment',
      req: 'Security and Compliance PowerShell with the Search And Purge role, which is not assigned by default.',
      more: [
        { id: 'name', label: 'Existing search name', type: 'text', placeholder: 'IR-phish-2026-09' },
        {
          id: 'type', label: 'Purge type', type: 'single', items: [
            { id: 'SoftDelete', label: 'Soft delete (recoverable by the user)', default: true },
            { id: 'HardDelete', label: 'Hard delete (unrecoverable)' }
          ]
        },
        { id: 'flags', label: 'Options', type: 'multi', items: [{ id: 'confirm', label: 'Ask for confirmation', default: true }, { id: 'status', label: 'Poll for the result', default: true }] }
      ],
      build: sel => {
        const name = q(sel.name) || 'IR-search';
        const lines = [
          '# A purge action removes up to 10 items per mailbox per run, and it cannot be undone.',
          "New-ComplianceSearchAction -SearchName '" + name + "' -Purge -PurgeType " + sel.type + (sel.flags.has('confirm') ? '' : ' -Confirm:$false')
        ];
        if (sel.flags.has('status')) {
          lines.push("Get-ComplianceSearchAction -Identity '" + name + "_Purge' | Format-List Name, Status, Results");
        }
        return lines.join('\n');
      }
    }
  );

  /* -------------------------------- SharePoint, OneDrive, Teams and Purview */

  add(
    {
      kind: 'ual',
      id: 'spo-file-activity',
      t: 'File activity for a user',
      p: ['SharePoint', 'Exfiltration'],
      d: 'Everything an account did with files in SharePoint and OneDrive: opened, changed, uploaded, renamed or downloaded.',
      k: 'fileaccessed filemodified fileuploaded filedownloaded filerenamed onedrive sharepoint documents changed files',
      days: 14, rec: 'SharePointFileOperation', ip: 1, obj: 1,
      ops: ['FileAccessed', 'FileDownloaded', 'FileModified', 'FileUploaded', 'FileRenamed', 'FileMoved', 'FileCopied', 'FilePreviewed', 'FileCheckedOut'],
      cols: [
        ['File', '$data.SourceFileName', true],
        ['Site', '$data.SiteUrl', true],
        ['Path', '$data.SourceRelativeUrl', true],
        ['App', '$data.ApplicationDisplayName', false]
      ]
    },
    {
      kind: 'ps',
      id: 'spo-mass-download',
      t: 'Mass download detection',
      p: ['SharePoint', 'Exfiltration'],
      d: 'Counts downloads and syncs per user per day and keeps the ones over a threshold, the shape of a staged data theft.',
      k: 'filedownloaded filesyncdownloadedfull mass download bulk exfiltration threshold per day spike leaver',
      more: [
        { id: 'days', label: 'Look back (days)', type: 'number', placeholder: '14', value: '14' },
        { id: 'min', label: 'Minimum files per user per day', type: 'number', placeholder: '100', value: '100' },
        { id: 'user', label: 'User (empty for all)', type: 'text', placeholder: 'jdoe@contoso.com' },
        {
          id: 'ops', label: 'Count', type: 'multi', items: [
            { id: 'FileDownloaded', label: 'Downloads', default: true },
            { id: 'FileSyncDownloadedFull', label: 'Sync client downloads', default: true },
            { id: 'FileAccessed', label: 'File opens' }
          ]
        }
      ],
      build: sel => {
        const ops = Array.from(sel.ops);
        const user = q(sel.user);
        return [
          '$start = (Get-Date).AddDays(-' + num(sel.days, 14) + ')',
          '$end = Get-Date',
          '$session = [guid]::NewGuid().ToString()',
          '$records = @()',
          'do {',
          '    $page = Search-UnifiedAuditLog -StartDate $start -EndDate $end `',
          '        -Operations ' + (ops.length ? ops.map(o => '"' + o + '"').join(', ') : '"FileDownloaded"') + ' `',
          (user ? "        -UserIds '" + user + "' `" : null),
          '        -ResultSize 5000 -SessionId $session -SessionCommand ReturnLargeSet',
          '    $records += $page',
          '} while ($page.Count -gt 0)',
          '$records |',
          "    Select-Object UserIds, Operations, @{N='Day';E={$_.CreationDate.ToString('yyyy-MM-dd')}} |",
          '    Group-Object UserIds, Day |',
          '    Where-Object { $_.Count -ge ' + num(sel.min, 100) + ' } |',
          "    Select-Object Count, @{N='User';E={$_.Group[0].UserIds}}, @{N='Day';E={$_.Group[0].Day}} |",
          '    Sort-Object Count -Descending |',
          '    Format-Table -AutoSize'
        ].filter(Boolean).join('\n');
      }
    },
    {
      kind: 'ual',
      id: 'spo-file-deleted',
      t: 'Files deleted or recycled',
      p: ['SharePoint', 'Anti-forensics'],
      d: 'Deletion events across SharePoint and OneDrive, for ransomware triage and for spotting evidence being removed.',
      k: 'filedeleted filerecycled folderdeleted recycle bin ransomware destruction deleted documents mass delete',
      days: 14, rec: 'SharePointFileOperation',
      ops: ['FileDeleted', 'FileRecycled', 'FileDeletedFirstStageRecycleBin', 'FileDeletedSecondStageRecycleBin', 'FolderDeleted', 'FolderRecycled', 'FileVersionsAllRecycled'],
      cols: [
        ['File', '$data.SourceFileName', true],
        ['Site', '$data.SiteUrl', true],
        ['Path', '$data.SourceRelativeUrl', true]
      ]
    },
    {
      kind: 'ual',
      id: 'spo-anonymous-links',
      t: 'Anonymous sharing links',
      p: ['SharePoint', 'Exfiltration'],
      d: 'Anyone-with-the-link sharing created or used, which is how data leaves a tenant without a single sign-in.',
      k: 'anonymouslinkcreated anonymouslinkused sharing link anyone external leak public link secure link',
      days: 30, rec: 'SharePointSharingOperation', ip: 1,
      ops: ['AnonymousLinkCreated', 'AnonymousLinkUsed', 'AnonymousLinkUpdated', 'SecureLinkCreated', 'SecureLinkUsed', 'CompanyLinkCreated', 'CompanyLinkUsed'],
      cols: [
        ['File', '$data.SourceFileName', true],
        ['Site', '$data.SiteUrl', true],
        ['TargetUser', '$data.TargetUserOrGroupName', true],
        ['LinkType', '$data.EventData', false, 'Contains the link scope and permission.']
      ]
    },
    {
      kind: 'ual',
      id: 'spo-external-sharing',
      t: 'Sharing with people outside the tenant',
      p: ['SharePoint', 'Exfiltration'],
      d: 'Sharing invitations and permission grants to guests, with the file and the address they were sent to.',
      k: 'sharingset sharinginvitationcreated guest external share added to secure link outside organisation',
      days: 30, rec: 'SharePointSharingOperation',
      ops: ['SharingSet', 'SharingInvitationCreated', 'SharingInvitationAccepted', 'AddedToSecureLink', 'SharingRevoked', 'AccessRequestCreated'],
      cols: [
        ['File', '$data.SourceFileName', true],
        ['Site', '$data.SiteUrl', true],
        ['SharedWith', '$data.TargetUserOrGroupName', true],
        ['TargetType', '$data.TargetUserOrGroupType', true, 'Guest means an account outside your tenant.']
      ]
    },
    {
      kind: 'ual',
      id: 'spo-permission-changes',
      t: 'Site permission changes',
      p: ['SharePoint', 'Privilege escalation'],
      d: 'Site collection admins and SharePoint group membership changes, which can hand over a whole site quietly.',
      k: 'sitecollectionadminadded addedtogroup permissionleveladded site owner group membership sharepoint permission',
      days: 30, rec: 'SharePoint',
      ops: ['SiteCollectionAdminAdded', 'SiteCollectionAdminRemoved', 'AddedToGroup', 'RemovedFromGroup', 'PermissionLevelAdded', 'PermissionLevelModified', 'SharingInheritanceBroken'],
      cols: [
        ['Site', '$data.SiteUrl', true],
        ['TargetUser', '$data.TargetUserOrGroupName', true],
        ['Details', '$data.EventData', false]
      ]
    },
    {
      kind: 'ual',
      id: 'spo-sync-events',
      t: 'OneDrive sync activity',
      p: ['SharePoint', 'Exfiltration'],
      d: 'Sync relationships and full downloads through the OneDrive client, including the ones blocked by device policy.',
      k: 'filesyncdownloadedfull managedsyncclientallowed unmanagedsyncclientblocked sync client onedrive copy local',
      days: 14, rec: 'SharePointFileOperation',
      ops: ['FileSyncDownloadedFull', 'FileSyncUploadedFull', 'ManagedSyncClientAllowed', 'UnmanagedSyncClientBlocked'],
      cols: [
        ['File', '$data.SourceFileName', true],
        ['Site', '$data.SiteUrl', true],
        ['Machine', '$data.MachineDisplayName', true],
        ['MachineDomain', '$data.MachineDomainInfo', false]
      ]
    },
    {
      kind: 'ual',
      id: 'teams-activity',
      t: 'Teams activity for an account',
      p: ['Teams', 'Collection'],
      d: 'Team and chat activity: sessions, membership, messages and exports, for the Teams part of an account takeover.',
      k: 'microsoftteams teamssessionstarted memberadded messagesent chatcreated messagesexported teams audit',
      days: 14, rec: 'MicrosoftTeams',
      ops: ['TeamsSessionStarted', 'MemberAdded', 'MemberRemoved', 'TeamCreated', 'TeamDeleted', 'ChatCreated', 'MessageSent', 'MessagesExported', 'MessageDeleted'],
      cols: [
        ['Team', '$data.TeamName', true],
        ['Channel', '$data.ChannelName', true],
        ['Members', "($data.Members | ForEach-Object { $_.UPN }) -join ', '", true],
        ['Details', '$data.ChatThreadId', false]
      ]
    },
    {
      kind: 'ual',
      id: 'teams-external-and-apps',
      t: 'Teams external access and app installs',
      p: ['Teams', 'Persistence'],
      d: 'Federation settings, shared channel invitations, bots and app installs, which is how Teams becomes a delivery channel.',
      k: 'teamstenantsettingchanged invitesent appinstalled botaddedtoteam connectoradded external access federation guest',
      days: 30, rec: 'MicrosoftTeams',
      ops: ['TeamsTenantSettingChanged', 'InviteSent', 'AppInstalled', 'AppPublishedToCatalog', 'AppUpdatedInCatalog', 'BotAddedToTeam', 'ConnectorAdded', 'TabAdded'],
      cols: [
        ['Team', '$data.TeamName', true],
        ['Setting', '$data.Name', true],
        ['NewValue', "($data.NewValue)", true],
        ['OldValue', '$data.OldValue', false]
      ]
    },
    {
      kind: 'ual',
      id: 'purview-ediscovery-activity',
      t: 'eDiscovery and content search activity',
      p: ['Purview', 'Exfiltration'],
      d: 'An attacker with compliance rights can read every mailbox through eDiscovery, so these records deserve review even when they look routine.',
      k: 'ediscovery content search purviewsearch export review set case hold abuse compliance mass collection',
      days: 90,
      ops: ['SearchCreated', 'SearchStarted', 'SearchExported', 'CaseAdded', 'HoldCreated', 'PurviewSearchAdded', 'PurviewSearchExportJobSubmitted', 'ReviewSetExportJobSubmitted', 'CaseMembersUpdated'],
      cols: [
        ['Case', '$data.CaseName', true],
        ['Object', '$data.ObjectName', true],
        ['Query', '$data.QueryText', true],
        ['Actor', '$data.UserId', true]
      ]
    },
    {
      kind: 'ual',
      id: 'purview-audit-searches',
      t: 'Who searched the audit log',
      p: ['Purview', 'Anti-forensics'],
      d: 'Audit searches and exports run in the portal, worth checking when you suspect the intruder is watching the investigation.',
      k: 'auditsearchcreated auditsearchexportjob downloaded who searched audit log counter forensics portal',
      days: 30,
      ops: ['AuditSearchCreated', 'AuditSearchCompleted', 'AuditSearchDeleted', 'AuditSearchExportJobCreated', 'AuditSearchExportResultsDownloaded'],
      cols: [
        ['SearchName', '$data.ObjectId', true],
        ['Actor', '$data.UserId', true]
      ]
    },
    {
      kind: 'ual',
      id: 'purview-dlp-events',
      t: 'DLP policy matches',
      p: ['Purview', 'Exfiltration'],
      d: 'Data loss prevention hits in mail and SharePoint, which often surface the exfiltration attempt before anything else does.',
      k: 'dlp policy match sensitive information type rule exchange sharepoint compliance exfiltration credit card',
      days: 14, rec: 'ComplianceDLPExchange',
      cols: [
        ['Policy', "($data.PolicyDetails | ForEach-Object { $_.PolicyName }) -join ', '", true],
        ['Rule', "($data.PolicyDetails.Rules | ForEach-Object { $_.RuleName }) -join ', '", true],
        ['Subject', '$data.ExchangeMetaData.Subject', true],
        ['Recipients', "($data.ExchangeMetaData.To) -join ', '", true],
        ['Severity', "($data.PolicyDetails.Rules | ForEach-Object { $_.Severity }) -join ', '", true]
      ]
    },
    {
      kind: 'ual',
      id: 'purview-policy-changes',
      t: 'Retention, label and alert policy changes',
      p: ['Purview', 'Anti-forensics'],
      d: 'Changes to retention, labels and alert policies can quietly shorten how long evidence lives, so review them during an incident.',
      k: 'newretentioncompliancepolicy setcompliancetag alert policy disabled retention shortened evidence destruction',
      days: 90,
      ops: ['NewRetentionCompliancePolicy', 'SetRetentionCompliancePolicy', 'RemoveRetentionCompliancePolicy', 'NewComplianceTag', 'SetComplianceTag', 'RemoveComplianceTag', 'New-ProtectionAlert', 'Set-ProtectionAlert', 'Remove-ProtectionAlert'],
      cols: [
        ['Object', '$data.ObjectId', true],
        ['Actor', '$data.UserId', true],
        ['Parameters', "($data.Parameters | ForEach-Object { $_.Name + '=' + $_.Value }) -join ' | '", true]
      ]
    },
    {
      kind: 'ps',
      id: 'purview-quarantine-messages',
      t: 'Quarantined messages',
      p: ['Purview', 'Phishing'],
      d: 'Lists what Defender for Office quarantined for a recipient or sender, and releases nothing until you say so.',
      k: 'get-quarantinemessage quarantine phish malware spam release preview recipient sender defender office',
      more: [
        { id: 'recipient', label: 'Recipient (optional)', type: 'text', placeholder: 'victim@contoso.com' },
        { id: 'sender', label: 'Sender (optional)', type: 'text', placeholder: 'attacker@evil.example' },
        { id: 'days', label: 'Look back (days)', type: 'number', placeholder: '7', value: '7' },
        {
          id: 'type', label: 'Quarantine type', type: 'single', items: [
            { id: 'all', label: 'All types', default: true },
            { id: 'Phish', label: 'Phish' },
            { id: 'HighConfPhish', label: 'High confidence phish' },
            { id: 'Malware', label: 'Malware' },
            { id: 'Spam', label: 'Spam' }
          ]
        }
      ],
      build: sel => {
        const args = ['-StartReceivedDate $start -EndReceivedDate $end'];
        if (q(sel.recipient)) args.push("-RecipientAddress '" + q(sel.recipient) + "'");
        if (q(sel.sender)) args.push("-SenderAddress '" + q(sel.sender) + "'");
        if (sel.type !== 'all') args.push('-Type ' + sel.type);
        return [
          '$start = (Get-Date).AddDays(-' + num(sel.days, 7) + ')',
          '$end = Get-Date',
          'Get-QuarantineMessage ' + args.join(' ') + ' -PageSize 1000 |',
          '    Select-Object ReceivedTime, SenderAddress, RecipientAddress, Subject, Type, PolicyName, Released, Identity |',
          '    Sort-Object ReceivedTime -Descending |',
          '    Format-Table -AutoSize'
        ].join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'purview-alerts',
      t: 'Alert policies and recent alerts',
      p: ['Purview', 'Triage'],
      d: 'Shows the alert policies in the tenant and whether any of them were disabled, which is a favourite pre-attack step.',
      k: 'get-protectionalert alert policy disabled notification threshold defender purview alerts triage',
      req: 'Security and Compliance PowerShell (Connect-IPPSSession).',
      more: [
        {
          id: 'report', label: 'Report', type: 'single', items: [
            { id: 'policies', label: 'Alert policies', default: true },
            { id: 'disabled', label: 'Disabled policies only' },
            { id: 'custom', label: 'Custom (not built in) policies' }
          ]
        }
      ],
      build: sel => {
        const lines = ['$alerts = Get-ProtectionAlert'];
        if (sel.report === 'disabled') lines.push("$alerts = $alerts | Where-Object { $_.Disabled -eq $true }");
        if (sel.report === 'custom') lines.push("$alerts = $alerts | Where-Object { -not $_.IsSystemRule }");
        lines.push('$alerts | Select-Object Name, Category, Severity, Disabled, IsSystemRule, ThreatType, NotifyUser, WhenChanged |');
        lines.push("    Sort-Object @{Expression='Disabled';Descending=$true}, Name |");
        lines.push('    Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      kind: 'ual',
      id: 'purview-label-changes',
      t: 'Sensitivity label changes',
      p: ['Purview', 'Exfiltration'],
      d: 'Labels being removed or downgraded on documents can be the step that lets data leave, so track the changes on sensitive sites.',
      k: 'sensitivitylabelapplied removed changed mip label downgrade justification document protection encryption removed',
      days: 30, rec: 'MipLabel',
      ops: ['FileSensitivityLabelApplied', 'FileSensitivityLabelChanged', 'FileSensitivityLabelRemoved', 'SensitivityLabelApplied', 'SensitivityLabelUpdated', 'SensitivityLabelRemoved'],
      cols: [
        ['File', '$data.SourceFileName', true],
        ['Site', '$data.SiteUrl', true],
        ['OldLabel', '$data.SensitivityLabelEventData.OldSensitivityLabelId', true],
        ['NewLabel', '$data.SensitivityLabelEventData.SensitivityLabelId', true]
      ]
    }
  );

  /* ---------------------------------------------- KQL hunting queries (XDR) */

  const SOURCE_OPT = {
    id: 'source', label: 'Data source', type: 'single', items: [
      { id: 'xdr', label: 'Defender XDR advanced hunting', default: true },
      { id: 'sentinel', label: 'Microsoft Sentinel (Log Analytics)' }
    ]
  };
  const LOOKBACK = (def) => ({ id: 'days', label: 'Look back (days)', type: 'number', placeholder: String(def), value: String(def) });

  function kqlUser(sel, column) {
    return q(sel.user) ? '| where ' + column + ' =~ "' + q(sel.user) + '"\n' : '';
  }

  add(
    {
      kind: 'kql',
      id: 'kql-device-code-signins',
      t: 'Hunt device code sign-ins',
      p: ['Hunting', 'Entra ID', 'Phishing'],
      d: 'Device code authentication in the sign-in tables, the query to run first when a device code phishing campaign is reported.',
      k: 'devicecode authenticationprotocol entraidsigninevents aadsignineventsbeta signinlogs phishing token theft hunting kql',
      more: [SOURCE_OPT, LOOKBACK(30), { id: 'user', label: 'User (optional)', type: 'text', placeholder: 'jdoe@contoso.com' },
        { id: 'flags', label: 'Options', type: 'multi', items: [{ id: 'successOnly', label: 'Successful sign-ins only', default: true }, { id: 'summarize', label: 'Summarise per user and app', default: true }] }],
      build: sel => {
        const days = num(sel.days, 30);
        if (sel.source === 'sentinel') {
          return [
            'SigninLogs',
            '| where TimeGenerated > ago(' + days + 'd)',
            '| where AuthenticationProtocol == "deviceCode"',
            sel.flags.has('successOnly') ? '| where ResultType == 0' : null,
            q(sel.user) ? '| where UserPrincipalName =~ "' + q(sel.user) + '"' : null,
            '| extend Country = tostring(LocationDetails.countryOrRegion)',
            sel.flags.has('summarize')
              ? '| summarize Attempts = count(), Countries = make_set(Country, 10), IPs = make_set(IPAddress, 10), First = min(TimeGenerated), Last = max(TimeGenerated) by UserPrincipalName, AppDisplayName\n| sort by Attempts desc'
              : '| project TimeGenerated, UserPrincipalName, AppDisplayName, ResourceDisplayName, IPAddress, Country, UserAgent, ResultType\n| sort by TimeGenerated desc'
          ].filter(Boolean).join('\n');
        }
        return [
          'EntraIdSignInEvents',
          '| where Timestamp > ago(' + days + 'd)',
          '// This table has no AuthenticationProtocol column, the device code flow shows up in the endpoint call.',
          '| where EndpointCall has "devicecode" or AuthenticationProcessingDetails has "device code"',
          sel.flags.has('successOnly') ? '| where ErrorCode == 0' : null,
          q(sel.user) ? '| where AccountUpn =~ "' + q(sel.user) + '"' : null,
          sel.flags.has('summarize')
            ? '| summarize Attempts = count(), Countries = make_set(Country, 10), IPs = make_set(IPAddress, 10), First = min(Timestamp), Last = max(Timestamp) by AccountUpn, Application\n| sort by Attempts desc'
            : '| project Timestamp, AccountUpn, Application, ResourceDisplayName, IPAddress, Country, UserAgent, ErrorCode\n| sort by Timestamp desc'
        ].filter(Boolean).join('\n');
      }
    },
    {
      kind: 'kql',
      id: 'kql-password-spray',
      t: 'Hunt password spraying',
      p: ['Hunting', 'Entra ID'],
      d: 'One source address failing against many different accounts in a short window, with the successes called out separately.',
      k: 'password spray brute force many accounts one ip 50126 failed logon hunting kql distinct accounts',
      more: [SOURCE_OPT, LOOKBACK(7), { id: 'min', label: 'Minimum distinct accounts per IP', type: 'number', placeholder: '10', value: '10' }],
      build: sel => {
        const days = num(sel.days, 7);
        const min = num(sel.min, 10);
        if (sel.source === 'sentinel') {
          return [
            'SigninLogs',
            '| where TimeGenerated > ago(' + days + 'd)',
            '| where ResultType in ("50126", "50053", "50055", "50056")',
            '| summarize Failures = count(), Accounts = dcount(UserPrincipalName), Targets = make_set(UserPrincipalName, 25),',
            '    Successes = countif(ResultType == "0"), First = min(TimeGenerated), Last = max(TimeGenerated)',
            '    by IPAddress, tostring(LocationDetails.countryOrRegion)',
            '| where Accounts >= ' + min,
            '| sort by Accounts desc'
          ].join('\n');
        }
        return [
          'EntraIdSignInEvents',
          '| where Timestamp > ago(' + days + 'd)',
          '| where ErrorCode in (50126, 50053, 50055, 50056)',
          '| summarize Failures = count(), Accounts = dcount(AccountUpn), Targets = make_set(AccountUpn, 25),',
          '    First = min(Timestamp), Last = max(Timestamp) by IPAddress, Country, Application',
          '| where Accounts >= ' + min,
          '| sort by Accounts desc'
        ].join('\n');
      }
    },
    {
      kind: 'kql',
      id: 'kql-impossible-travel',
      t: 'Hunt sign-ins from several countries',
      p: ['Hunting', 'Entra ID'],
      d: 'Accounts that authenticated successfully from more than one country in a short window, the cheap version of impossible travel.',
      k: 'impossible travel countries per user atypical location anomalous geography kql dcount country',
      more: [SOURCE_OPT, LOOKBACK(7), { id: 'window', label: 'Window in hours', type: 'number', placeholder: '6', value: '6' }],
      build: sel => {
        const days = num(sel.days, 7);
        const win = num(sel.window, 6);
        if (sel.source === 'sentinel') {
          return [
            'SigninLogs',
            '| where TimeGenerated > ago(' + days + 'd)',
            '| where ResultType == 0',
            '| extend Country = tostring(LocationDetails.countryOrRegion)',
            '| summarize Countries = make_set(Country), CountryCount = dcount(Country), IPs = make_set(IPAddress, 10)',
            '    by UserPrincipalName, bin(TimeGenerated, ' + win + 'h)',
            '| where CountryCount > 1',
            '| sort by CountryCount desc, TimeGenerated desc'
          ].join('\n');
        }
        return [
          'EntraIdSignInEvents',
          '| where Timestamp > ago(' + days + 'd)',
          '| where ErrorCode == 0',
          '| summarize Countries = make_set(Country), CountryCount = dcount(Country), IPs = make_set(IPAddress, 10)',
          '    by AccountUpn, bin(Timestamp, ' + win + 'h)',
          '| where CountryCount > 1',
          '| sort by CountryCount desc, Timestamp desc'
        ].join('\n');
      }
    },
    {
      kind: 'kql',
      id: 'kql-legacy-auth',
      t: 'Hunt legacy authentication',
      p: ['Hunting', 'Entra ID'],
      d: 'Successful sign-ins over IMAP, POP, SMTP and other clients that cannot present MFA.',
      k: 'clientappused legacy imap pop smtp other clients mfa bypass basic auth kql hunting',
      more: [SOURCE_OPT, LOOKBACK(14)],
      build: sel => {
        const days = num(sel.days, 14);
        if (sel.source === 'sentinel') {
          return [
            'SigninLogs',
            '| where TimeGenerated > ago(' + days + 'd)',
            '| where ClientAppUsed in ("IMAP4", "POP3", "SMTP", "Exchange ActiveSync", "Other clients", "Authenticated SMTP")',
            '| where ResultType == 0',
            '| summarize SignIns = count(), IPs = make_set(IPAddress, 10), Apps = make_set(AppDisplayName, 10),',
            '    Last = max(TimeGenerated) by UserPrincipalName, ClientAppUsed',
            '| sort by SignIns desc'
          ].join('\n');
        }
        return [
          'EntraIdSignInEvents',
          '| where Timestamp > ago(' + days + 'd)',
          '| where ClientAppUsed in ("IMAP4", "POP3", "SMTP", "Exchange ActiveSync", "Other clients", "Authenticated SMTP")',
          '| where ErrorCode == 0',
          '| summarize SignIns = count(), IPs = make_set(IPAddress, 10), Last = max(Timestamp) by AccountUpn, ClientAppUsed',
          '| sort by SignIns desc'
        ].join('\n');
      }
    },
    {
      kind: 'kql',
      id: 'kql-mfa-fatigue',
      t: 'Hunt MFA fatigue and denied prompts',
      p: ['Hunting', 'Entra ID'],
      d: 'Repeated MFA prompts that the user denied or let time out, the signal of an attacker holding a valid password.',
      k: 'mfa fatigue push bombing 500121 50074 denied timeout repeated prompts hunting kql authentication',
      more: [SOURCE_OPT, LOOKBACK(7), { id: 'min', label: 'Minimum denied prompts', type: 'number', placeholder: '5', value: '5' }],
      build: sel => {
        const days = num(sel.days, 7);
        const min = num(sel.min, 5);
        if (sel.source === 'sentinel') {
          return [
            'SigninLogs',
            '| where TimeGenerated > ago(' + days + 'd)',
            '| where ResultType in ("500121", "50074", "50076", "50072")',
            '| summarize Denied = count(), IPs = make_set(IPAddress, 10), Apps = make_set(AppDisplayName, 5),',
            '    First = min(TimeGenerated), Last = max(TimeGenerated) by UserPrincipalName, bin(TimeGenerated, 1h)',
            '| where Denied >= ' + min,
            '| sort by Denied desc'
          ].join('\n');
        }
        return [
          'EntraIdSignInEvents',
          '| where Timestamp > ago(' + days + 'd)',
          '| where ErrorCode in (500121, 50074, 50076, 50072)',
          '| summarize Denied = count(), IPs = make_set(IPAddress, 10), Last = max(Timestamp)',
          '    by AccountUpn, bin(Timestamp, 1h)',
          '| where Denied >= ' + min,
          '| sort by Denied desc'
        ].join('\n');
      }
    },
    {
      kind: 'kql',
      id: 'kql-inbox-rule-created',
      t: 'Hunt inbox rule creation',
      p: ['Hunting', 'Exchange Online', 'Persistence'],
      d: 'Rule creation in CloudAppEvents with the raw parameters, so forwarding and delete rules stand out immediately.',
      k: 'cloudappevents new-inboxrule set-inboxrule updateinboxrules rawevent data forwardto deletemessage hunting',
      more: [LOOKBACK(14), { id: 'user', label: 'User (optional)', type: 'text', placeholder: 'jdoe@contoso.com' },
        { id: 'flags', label: 'Filter', type: 'multi', items: [{ id: 'suspicious', label: 'Only rules that forward or delete', default: true }] }],
      build: sel => {
        const lines = [
          'CloudAppEvents',
          '| where Timestamp > ago(' + num(sel.days, 14) + 'd)',
          '| where ActionType in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")',
          kqlUser(sel, 'AccountDisplayName').trim() || null,
          '| extend Parameters = tostring(RawEventData.Parameters)',
          '| extend RuleName = tostring(parse_json(tostring(RawEventData.Parameters))[0].Value)'
        ].filter(Boolean);
        if (sel.flags.has('suspicious')) {
          lines.push('| where Parameters has_any ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "DeleteMessage", "MoveToFolder")');
        }
        lines.push('| project Timestamp, AccountDisplayName, ActionType, RuleName, Parameters, IPAddress, UserAgent');
        lines.push('| sort by Timestamp desc');
        return lines.join('\n');
      }
    },
    {
      kind: 'kql',
      id: 'kql-consent-grant',
      t: 'Hunt illicit consent grants',
      p: ['Hunting', 'Applications', 'Phishing'],
      d: 'Consent events with the granted scopes, so a Mail.Read or Files.ReadWrite grant to an unknown app is easy to spot.',
      k: 'cloudappevents consent to application oauth illicit grant scopes isadminconsent hunting application',
      more: [LOOKBACK(30), { id: 'flags', label: 'Filter', type: 'multi', items: [{ id: 'risky', label: 'Risky scopes only', default: true }, { id: 'admin', label: 'Admin consent only' }] }],
      build: sel => {
        const lines = [
          'CloudAppEvents',
          '| where Timestamp > ago(' + num(sel.days, 30) + 'd)',
          '| where ActionType in ("Consent to application.", "Add delegation entry.", "Add app role assignment grant to user.")',
          '| extend Details = tostring(RawEventData.ModifiedProperties)',
          '| extend Actor = tostring(RawEventData.UserId)'
        ];
        if (sel.flags.has('risky')) lines.push('| where Details has_any ("Mail.", "Files.", "Contacts.", "MailboxSettings.", "Directory.ReadWrite", "user_impersonation", "offline_access")');
        if (sel.flags.has('admin')) lines.push('| where Details has "IsAdminConsent" and Details has "True"');
        lines.push('| project Timestamp, AccountDisplayName, ActionType, Details, IPAddress, UserAgent');
        lines.push('| sort by Timestamp desc');
        return lines.join('\n');
      }
    },
    {
      kind: 'kql',
      id: 'kql-service-principal-credentials',
      t: 'Hunt credentials added to applications',
      p: ['Hunting', 'Applications', 'Persistence'],
      d: 'New secrets and certificates on service principals, the persistence step that survives every user password reset.',
      k: 'add service principal credentials keycredential secret certificate persistence app-only hunting cloudappevents',
      more: [LOOKBACK(90)],
      build: sel => [
        'CloudAppEvents',
        '| where Timestamp > ago(' + num(sel.days, 90) + 'd)',
        '| where ActionType in ("Add service principal credentials.", "Update application.", "Add service principal.")',
        '| extend Target = tostring(RawEventData.Target)',
        '| extend Details = tostring(RawEventData.ModifiedProperties)',
        '| where Details has_any ("KeyDescription", "PasswordCredentials", "KeyCredentials")',
        '| project Timestamp, AccountDisplayName, ActionType, Target, Details, IPAddress',
        '| sort by Timestamp desc'
      ].join('\n')
    },
    {
      kind: 'kql',
      id: 'kql-mail-items-accessed',
      t: 'Hunt bulk mailbox access',
      p: ['Hunting', 'Exchange Online', 'Exfiltration'],
      d: 'MailItemsAccessed records where the access type is a sync, which means a whole folder left the tenant.',
      k: 'mailitemsaccessed sync bind cloudappevents mailbox read exfiltration bulk folders hunting',
      more: [LOOKBACK(14), { id: 'user', label: 'Mailbox (optional)', type: 'text', placeholder: 'jdoe@contoso.com' },
        { id: 'flags', label: 'Filter', type: 'multi', items: [{ id: 'sync', label: 'Sync operations only', default: true }] }],
      build: sel => {
        const lines = [
          'CloudAppEvents',
          '| where Timestamp > ago(' + num(sel.days, 14) + 'd)',
          '| where ActionType == "MailItemsAccessed"',
          kqlUser(sel, 'AccountDisplayName').trim() || null,
          '| extend Properties = tostring(RawEventData.OperationProperties)'
        ].filter(Boolean);
        if (sel.flags.has('sync')) lines.push('| where Properties has "Sync"');
        lines.push('| extend Folders = tostring(RawEventData.Folders)');
        lines.push('| project Timestamp, AccountDisplayName, IPAddress, UserAgent, Properties, Folders');
        lines.push('| sort by Timestamp desc');
        return lines.join('\n');
      }
    },
    {
      kind: 'kql',
      id: 'kql-mass-download',
      t: 'Hunt mass file downloads',
      p: ['Hunting', 'SharePoint', 'Exfiltration'],
      d: 'Counts downloads per account per hour in CloudAppEvents and keeps the spikes.',
      k: 'filedownloaded filesyncdownloadedfull mass download exfiltration spike per hour hunting cloudappevents',
      more: [LOOKBACK(14), { id: 'min', label: 'Minimum files per hour', type: 'number', placeholder: '50', value: '50' }],
      build: sel => [
        'CloudAppEvents',
        '| where Timestamp > ago(' + num(sel.days, 14) + 'd)',
        '| where ActionType in ("FileDownloaded", "FileSyncDownloadedFull", "FileAccessed")',
        '| summarize Files = count(), Types = make_set(ActionType), IPs = make_set(IPAddress, 5),',
        '    Sites = dcount(tostring(RawEventData.SiteUrl)) by AccountDisplayName, bin(Timestamp, 1h)',
        '| where Files >= ' + num(sel.min, 50),
        '| sort by Files desc'
      ].join('\n')
    },
    {
      kind: 'kql',
      id: 'kql-phishing-url-clicks',
      t: 'Hunt who clicked a phishing link',
      p: ['Hunting', 'Phishing'],
      d: 'Joins the delivered mail with the Safe Links click events, which gives the list of users who actually clicked.',
      k: 'urlclickevents emailevents emailurlinfo safe links clicked phishing campaign delivered blocked hunting',
      more: [LOOKBACK(14), { id: 'sender', label: 'Sender or domain (optional)', type: 'text', placeholder: 'evil.example' },
        { id: 'flags', label: 'Filter', type: 'multi', items: [{ id: 'clickedThrough', label: 'Only clicks that were allowed through', default: true }] }],
      build: sel => {
        const lines = [
          'let lookback = ' + num(sel.days, 14) + 'd;',
          'let clicks = UrlClickEvents',
          '    | where Timestamp > ago(lookback)'
        ];
        if (sel.flags.has('clickedThrough')) lines.push('    | where ActionType == "ClickAllowed" or IsClickedThrough != "0"');
        lines.push('    | project ClickTime = Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, NetworkMessageId;');
        lines.push('EmailEvents');
        lines.push('| where Timestamp > ago(lookback)');
        if (q(sel.sender)) lines.push('| where SenderFromAddress has "' + q(sel.sender) + '" or SenderMailFromDomain has "' + q(sel.sender) + '"');
        lines.push('| join kind=inner clicks on NetworkMessageId');
        lines.push('| project ClickTime, AccountUpn, RecipientEmailAddress, SenderFromAddress, Subject, Url, ActionType, DeliveryAction');
        lines.push('| sort by ClickTime desc');
        return lines.join('\n');
      }
    },
    {
      kind: 'kql',
      id: 'kql-risky-signin-then-rule',
      t: 'Hunt a risky sign-in followed by a mailbox rule',
      p: ['Hunting', 'Exchange Online', 'Persistence'],
      d: 'Correlates a risky or foreign sign-in with an inbox rule created shortly after, the classic business email compromise pattern.',
      k: 'correlation risky signin inbox rule created after compromise bec join time window hunting',
      more: [LOOKBACK(14), { id: 'window', label: 'Rule created within (hours)', type: 'number', placeholder: '24', value: '24' }],
      build: sel => [
        'let lookback = ' + num(sel.days, 14) + 'd;',
        'let window = ' + num(sel.window, 24) + 'h;',
        'let risky = EntraIdSignInEvents',
        '    | where Timestamp > ago(lookback)',
        '    | where ErrorCode == 0 and RiskLevelDuringSignIn >= 50',
        '    | project SignInTime = Timestamp, AccountUpn, IPAddress, Country, Application;',
        'CloudAppEvents',
        '| where Timestamp > ago(lookback)',
        '| where ActionType in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")',
        '| extend AccountUpn = tolower(AccountDisplayName)',
        '| join kind=inner risky on AccountUpn',
        '| where Timestamp between (SignInTime .. (SignInTime + window))',
        '| project SignInTime, RuleTime = Timestamp, AccountUpn, Country, IPAddress, ActionType, Parameters = tostring(RawEventData.Parameters)',
        '| sort by RuleTime desc'
      ].join('\n')
    },
    {
      kind: 'kql',
      id: 'kql-account-timeline',
      t: 'One account across every table',
      p: ['Hunting', 'Collection'],
      d: 'Unions identity, cloud app, email and device events for a single account into one ordered timeline.',
      k: 'union timeline single account all tables identitylogonevents cloudappevents emailevents devicelogonevents hunting',
      more: [LOOKBACK(7), { id: 'user', label: 'User (UPN)', type: 'text', placeholder: 'jdoe@contoso.com' }],
      build: sel => {
        const user = q(sel.user) || 'jdoe@contoso.com';
        return [
          'let lookback = ' + num(sel.days, 7) + 'd;',
          'let account = "' + user + '";',
          'union isfuzzy=true',
          '    (EntraIdSignInEvents',
          '        | where Timestamp > ago(lookback) and AccountUpn =~ account',
          '        | project Timestamp, Source = "SignIn", Action = Application, Details = strcat(Country, " ", IPAddress, " err=", ErrorCode)),',
          '    (CloudAppEvents',
          '        | where Timestamp > ago(lookback) and AccountDisplayName =~ account',
          '        | project Timestamp, Source = "CloudApp", Action = ActionType, Details = strcat(Application, " ", IPAddress)),',
          '    (EmailEvents',
          '        | where Timestamp > ago(lookback) and (SenderFromAddress =~ account or RecipientEmailAddress =~ account)',
          '        | project Timestamp, Source = "Email", Action = DeliveryAction, Details = strcat(SenderFromAddress, " -> ", RecipientEmailAddress, " : ", Subject)),',
          '    (IdentityLogonEvents',
          '        | where Timestamp > ago(lookback) and AccountUpn =~ account',
          '        | project Timestamp, Source = "Identity", Action = LogonType, Details = strcat(DeviceName, " ", IPAddress))',
          '| sort by Timestamp desc'
        ].join('\n');
      }
    },
    {
      kind: 'kql',
      id: 'kql-alerts-for-account',
      t: 'Defender alerts and evidence for an account',
      p: ['Hunting', 'Triage'],
      d: 'Pulls the alerts that touch one account or device together with their evidence rows, as a triage starting point.',
      k: 'alertinfo alertevidence incident severity title entities triage defender xdr hunting correlate',
      more: [LOOKBACK(30), { id: 'user', label: 'User or device (optional)', type: 'text', placeholder: 'jdoe@contoso.com' },
        { id: 'severity', label: 'Minimum severity', type: 'single', items: [{ id: 'all', label: 'All severities', default: true }, { id: 'Medium', label: 'Medium and above' }, { id: 'High', label: 'High only' }] }],
      build: sel => {
        const lines = [
          'let lookback = ' + num(sel.days, 30) + 'd;',
          'AlertInfo',
          '| where Timestamp > ago(lookback)'
        ];
        if (sel.severity === 'High') lines.push('| where Severity == "High"');
        if (sel.severity === 'Medium') lines.push('| where Severity in ("High", "Medium")');
        lines.push('| join kind=inner (AlertEvidence | where Timestamp > ago(lookback)) on AlertId');
        if (q(sel.user)) lines.push('| where AccountUpn =~ "' + q(sel.user) + '" or DeviceName has "' + q(sel.user) + '"');
        lines.push('| project Timestamp, AlertId, Title, Severity, Category, ServiceSource, EntityType, AccountUpn, DeviceName, RemoteIP, FileName');
        lines.push('| sort by Timestamp desc');
        return lines.join('\n');
      }
    }
  );

  /* -------------------------------------------- containment and remediation */

  add(
    {
      kind: 'ps',
      id: 'resp-contain-account',
      t: 'Contain a compromised account',
      p: ['Containment', 'Identity'],
      d: 'The standard containment sequence in one place: block sign-in, revoke every token, reset the password and strip the attacker persistence.',
      k: 'containment compromised account block sign-in revoke sessions reset password remove rules forwarding response playbook',
      req: 'Microsoft.Graph and ExchangeOnlineManagement, with User.ReadWrite.All and mailbox admin rights.',
      more: [
        { id: 'user', label: 'Account (UPN)', type: 'text', placeholder: 'jdoe@contoso.com' },
        {
          id: 'steps', label: 'Steps', type: 'multi', wide: true, items: [
            { id: 'block', label: 'Block sign-in', default: true },
            { id: 'revoke', label: 'Revoke refresh tokens and sessions', default: true },
            { id: 'password', label: 'Reset the password', default: true },
            { id: 'rules', label: 'Remove inbox rules', default: true },
            { id: 'forward', label: 'Clear mailbox forwarding', default: true },
            { id: 'oof', label: 'Turn off the automatic reply', default: true },
            { id: 'legacy', label: 'Disable IMAP, POP and SMTP AUTH', default: true },
            { id: 'devices', label: 'Remove the ActiveSync partnerships' },
            { id: 'mfa', label: 'List the registered MFA methods to review', default: true }
          ]
        },
        { id: 'flags', label: 'Options', type: 'multi', items: [{ id: 'whatIf', label: 'Dry run where the cmdlet supports it', default: true }] }
      ],
      build: sel => {
        const user = q(sel.user) || 'jdoe@contoso.com';
        const whatIf = sel.flags.has('whatIf') ? ' -WhatIf' : '';
        const lines = ["$user = '" + user + "'"];
        if (sel.steps.has('block')) {
          lines.push('$account = Get-MgUser -UserId $user');
          lines.push('Update-MgUser -UserId $account.Id -AccountEnabled:$false');
        }
        if (sel.steps.has('revoke')) lines.push('Revoke-MgUserSignInSession -UserId $user');
        if (sel.steps.has('password')) {
          lines.push("$password = -join ((33..126) | Get-Random -Count 24 | ForEach-Object { [char]$_ })");
          lines.push('Update-MgUser -UserId $user -PasswordProfile @{ ForceChangePasswordNextSignIn = $true; Password = $password }');
          lines.push('Write-Host "Temporary password: $password"');
        }
        if (sel.steps.has('rules')) {
          lines.push('Get-InboxRule -Mailbox $user | ForEach-Object {');
          lines.push('    Write-Host "Removing rule: $($_.Name) -> $($_.ForwardTo) $($_.RedirectTo)"');
          lines.push('    Remove-InboxRule -Mailbox $user -Identity $_.Identity -Confirm:$false' + whatIf);
          lines.push('}');
        }
        if (sel.steps.has('forward')) lines.push('Set-Mailbox -Identity $user -ForwardingSmtpAddress $null -ForwardingAddress $null -DeliverToMailboxAndForward $false' + whatIf);
        if (sel.steps.has('oof')) lines.push('Set-MailboxAutoReplyConfiguration -Identity $user -AutoReplyState Disabled -InternalMessage $null -ExternalMessage $null' + whatIf);
        if (sel.steps.has('legacy')) lines.push('Set-CASMailbox -Identity $user -ImapEnabled $false -PopEnabled $false -SmtpClientAuthenticationDisabled $true' + whatIf);
        if (sel.steps.has('devices')) {
          lines.push('Get-MobileDevice -Mailbox $user | ForEach-Object {');
          lines.push('    Remove-MobileDevice -Identity $_.Identity -Confirm:$false' + whatIf);
          lines.push('}');
        }
        if (sel.steps.has('mfa')) {
          lines.push('Get-MgUserAuthenticationMethod -UserId $user |');
          lines.push("    Select-Object Id, @{N='Type';E={$_.AdditionalProperties['@odata.type']}} |");
          lines.push('    Format-Table -AutoSize');
        }
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'resp-revoke-sessions',
      t: 'Revoke tokens and active sessions',
      p: ['Containment', 'Identity'],
      d: 'A password reset alone leaves stolen refresh tokens working, so revoke the sessions and confirm the token issue time moved.',
      k: 'revoke-mgusersigninsession refreshtokensvalidfromdatetime token theft session revoke stolen cookie aitm',
      req: 'Microsoft.Graph module with User.RevokeSessions.All.',
      more: [
        { id: 'user', label: 'Account (UPN), or a group name', type: 'text', placeholder: 'jdoe@contoso.com' },
        {
          id: 'scope', label: 'Scope', type: 'single', items: [
            { id: 'user', label: 'One account', default: true },
            { id: 'group', label: 'Every member of a group' },
            { id: 'admins', label: 'Every global administrator' }
          ]
        },
        { id: 'flags', label: 'After', type: 'multi', items: [{ id: 'verify', label: 'Show the new token validity date', default: true }] }
      ],
      build: sel => {
        const target = q(sel.user) || 'jdoe@contoso.com';
        const lines = [];
        if (sel.scope === 'group') {
          lines.push("$group = Get-MgGroup -Filter \"displayName eq '" + target + "'\"");
          lines.push('$members = Get-MgGroupMember -GroupId $group.Id -All');
          lines.push('$members | ForEach-Object { Revoke-MgUserSignInSession -UserId $_.Id }');
        } else if (sel.scope === 'admins') {
          lines.push("$role = Get-MgDirectoryRole -Filter \"displayName eq 'Global Administrator'\"");
          lines.push('$members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id');
          lines.push('$members | ForEach-Object { Revoke-MgUserSignInSession -UserId $_.Id }');
        } else {
          lines.push("Revoke-MgUserSignInSession -UserId '" + target + "'");
        }
        if (sel.flags.has('verify')) {
          lines.push("Get-MgUser -UserId '" + target + "' -Property UserPrincipalName, SignInSessionsValidFromDateTime |");
          lines.push('    Format-List UserPrincipalName, SignInSessionsValidFromDateTime');
        }
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'resp-remove-inbox-rules',
      t: 'Remove malicious inbox rules',
      p: ['Containment', 'Exchange Online'],
      d: 'Exports the rules first as evidence, then deletes the ones that forward, redirect or delete mail.',
      k: 'remove-inboxrule delete malicious rule evidence export backup json remediation forwarding cleanup',
      more: [
        { id: 'user', label: 'Mailbox (empty for all)', type: 'text', placeholder: 'jdoe@contoso.com' },
        {
          id: 'target', label: 'Remove rules that', type: 'multi', items: [
            { id: 'forward', label: 'Forward or redirect', default: true },
            { id: 'delete', label: 'Delete messages', default: true },
            { id: 'all', label: 'Everything (leave nothing)' }
          ]
        },
        { id: 'flags', label: 'Options', type: 'multi', items: [{ id: 'backup', label: 'Export the rules to JSON first', default: true }, { id: 'whatIf', label: 'Dry run (-WhatIf)', default: true }] }
      ],
      build: sel => {
        const user = q(sel.user);
        const whatIf = sel.flags.has('whatIf') ? ' -WhatIf' : '';
        const lines = ['$mailboxes = Get-Mailbox ' + (user ? "-Identity '" + user + "'" : '-ResultSize Unlimited')];
        lines.push('foreach ($mailbox in $mailboxes) {');
        lines.push('    $rules = Get-InboxRule -Mailbox $mailbox.UserPrincipalName -ErrorAction SilentlyContinue');
        if (sel.flags.has('backup')) {
          lines.push('    if ($rules) {');
          lines.push('        $rules | ConvertTo-Json -Depth 5 | Out-File ".\\InboxRules-$($mailbox.Alias).json" -Encoding UTF8');
          lines.push('    }');
        }
        if (!sel.target.has('all')) {
          const tests = [];
          if (sel.target.has('forward')) tests.push('$_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo');
          if (sel.target.has('delete')) tests.push('$_.DeleteMessage');
          lines.push('    $rules = $rules | Where-Object { ' + (tests.join(' -or ') || '$false') + ' }');
        }
        lines.push('    foreach ($rule in $rules) {');
        lines.push('        Write-Host "$($mailbox.UserPrincipalName): removing $($rule.Name)"');
        lines.push('        Remove-InboxRule -Mailbox $mailbox.UserPrincipalName -Identity $rule.Identity -Confirm:$false' + whatIf);
        lines.push('    }');
        lines.push('}');
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'resp-clear-forwarding',
      t: 'Clear forwarding across the tenant',
      p: ['Containment', 'Exchange Online'],
      d: 'Finds every mailbox forwarding outside the organisation and clears it, with a CSV of what was changed.',
      k: 'forwardingsmtpaddress clear remove external forwarding tenant wide remediation csv log bulk',
      more: [
        { id: 'flags', label: 'Options', type: 'multi', items: [{ id: 'log', label: 'Write a CSV of the changes first', default: true }, { id: 'whatIf', label: 'Dry run (-WhatIf)', default: true }] },
        { id: 'extra', label: 'Also', type: 'multi', items: [{ id: 'remote', label: 'Turn off auto forwarding on remote domains' }] }
      ],
      build: sel => {
        const whatIf = sel.flags.has('whatIf') ? ' -WhatIf' : '';
        const lines = [
          '$domains = (Get-AcceptedDomain).DomainName',
          '$forwarding = Get-Mailbox -ResultSize Unlimited |',
          '    Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress } |',
          '    Select-Object UserPrincipalName, ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward'
        ];
        if (sel.flags.has('log')) lines.push('$forwarding | Export-Csv -Path .\\ForwardingBeforeCleanup.csv -NoTypeInformation -Encoding UTF8');
        lines.push('$forwarding | ForEach-Object {');
        lines.push('    Set-Mailbox -Identity $_.UserPrincipalName -ForwardingSmtpAddress $null -ForwardingAddress $null -DeliverToMailboxAndForward $false' + whatIf);
        lines.push('}');
        if (sel.extra.has('remote')) lines.push('Get-RemoteDomain | Set-RemoteDomain -AutoForwardEnabled $false' + whatIf);
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'resp-reset-mfa',
      t: 'Reset the MFA registration of a user',
      p: ['Containment', 'Identity'],
      d: 'Removes the registered authentication methods so the user has to enrol again, which drops any attacker enrolled factor.',
      k: 'remove authentication method reregister mfa reset authenticator phone fido attacker enrolled persistence',
      req: 'Microsoft.Graph module with UserAuthenticationMethod.ReadWrite.All.',
      more: [
        { id: 'user', label: 'Account (UPN)', type: 'text', placeholder: 'jdoe@contoso.com' },
        {
          id: 'methods', label: 'Remove', type: 'multi', items: [
            { id: 'phone', label: 'Phone methods', default: true },
            { id: 'authenticator', label: 'Microsoft Authenticator', default: true },
            { id: 'fido', label: 'FIDO2 keys' },
            { id: 'software', label: 'Software OATH tokens', default: true }
          ]
        },
        { id: 'flags', label: 'Options', type: 'multi', items: [{ id: 'list', label: 'List the methods first', default: true }] }
      ],
      build: sel => {
        const user = q(sel.user) || 'jdoe@contoso.com';
        const lines = ["$user = '" + user + "'"];
        if (sel.flags.has('list')) {
          lines.push('Get-MgUserAuthenticationMethod -UserId $user |');
          lines.push("    Select-Object Id, @{N='Type';E={$_.AdditionalProperties['@odata.type']}} |");
          lines.push('    Format-Table -AutoSize');
        }
        if (sel.methods.has('phone')) {
          lines.push('Get-MgUserAuthenticationPhoneMethod -UserId $user | ForEach-Object {');
          lines.push('    Remove-MgUserAuthenticationPhoneMethod -UserId $user -PhoneAuthenticationMethodId $_.Id');
          lines.push('}');
        }
        if (sel.methods.has('authenticator')) {
          lines.push('Get-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $user | ForEach-Object {');
          lines.push('    Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $user -MicrosoftAuthenticatorAuthenticationMethodId $_.Id');
          lines.push('}');
        }
        if (sel.methods.has('fido')) {
          lines.push('Get-MgUserAuthenticationFido2Method -UserId $user | ForEach-Object {');
          lines.push('    Remove-MgUserAuthenticationFido2Method -UserId $user -Fido2AuthenticationMethodId $_.Id');
          lines.push('}');
        }
        if (sel.methods.has('software')) {
          lines.push('Get-MgUserAuthenticationSoftwareOathMethod -UserId $user | ForEach-Object {');
          lines.push('    Remove-MgUserAuthenticationSoftwareOathMethod -UserId $user -SoftwareOathAuthenticationMethodId $_.Id');
          lines.push('}');
        }
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'resp-disable-user-devices',
      t: 'Disable the devices of an account',
      p: ['Containment', 'Identity'],
      d: 'Lists and disables the Entra registered devices of a user, which blocks the primary refresh tokens tied to them.',
      k: 'get-mguserregistereddevice disable device prt entra joined registered containment revoke device token',
      req: 'Microsoft.Graph module with Device.ReadWrite.All.',
      more: [
        { id: 'user', label: 'Account (UPN)', type: 'text', placeholder: 'jdoe@contoso.com' },
        {
          id: 'mode', label: 'Action', type: 'single', items: [
            { id: 'list', label: 'List the devices', default: true },
            { id: 'disable', label: 'Disable them' }
          ]
        }
      ],
      build: sel => {
        const user = q(sel.user) || 'jdoe@contoso.com';
        const lines = [
          "$devices = Get-MgUserRegisteredDevice -UserId '" + user + "' -All",
          '$devices | ForEach-Object { $_.AdditionalProperties } |',
          '    Select-Object displayName, operatingSystem, trustType, isCompliant, approximateLastSignInDateTime |',
          '    Format-Table -AutoSize'
        ];
        if (sel.mode === 'disable') {
          lines.push('$devices | ForEach-Object {');
          lines.push('    Update-MgDevice -DeviceId $_.Id -AccountEnabled:$false');
          lines.push('}');
        }
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'resp-restrict-user-consent',
      t: 'Stop users consenting to applications',
      p: ['Containment', 'Applications', 'Hardening'],
      d: 'Turns off or narrows user consent so the same consent phish cannot work twice, and switches on the admin approval workflow.',
      k: 'permissiongrantpolicy user consent disable restrict verified publisher admin consent workflow hardening authorizationpolicy',
      req: 'Microsoft.Graph module with Policy.ReadWrite.Authorization.',
      more: [
        {
          id: 'mode', label: 'Setting', type: 'single', items: [
            { id: 'show', label: 'Show the current setting', default: true },
            { id: 'off', label: 'Block all user consent' },
            { id: 'limited', label: 'Allow only low impact permissions from verified publishers' }
          ]
        },
        { id: 'flags', label: 'Also', type: 'multi', items: [{ id: 'appreg', label: 'Stop users registering applications' }] }
      ],
      build: sel => {
        const lines = [];
        if (sel.mode === 'show') {
          lines.push('$policy = Get-MgPolicyAuthorizationPolicy');
          lines.push('$policy.DefaultUserRolePermissions | Format-List AllowedToCreateApps, PermissionGrantPoliciesAssigned');
        } else if (sel.mode === 'off') {
          lines.push('Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{ PermissionGrantPoliciesAssigned = @() }');
        } else {
          lines.push('Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{');
          lines.push("    PermissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.microsoft-user-default-low')");
          lines.push('}');
        }
        if (sel.flags.has('appreg')) lines.push('Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{ AllowedToCreateApps = $false }');
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'resp-block-sender',
      t: 'Block a sender, domain or file',
      p: ['Containment', 'Phishing'],
      d: 'Adds the attacker sender, domain, URL or file hash to the tenant allow and block list with an expiry date.',
      k: 'new-tenantallowblocklistitems block sender domain url filehash defender office tenant allow block list',
      more: [
        {
          id: 'type', label: 'Entry type', type: 'single', items: [
            { id: 'Sender', label: 'Sender or domain', default: true },
            { id: 'Url', label: 'URL' },
            { id: 'FileHash', label: 'File hash (SHA256)' }
          ]
        },
        { id: 'value', label: 'Value to block', type: 'text', placeholder: 'evil.example' },
        { id: 'days', label: 'Expire after (days), empty for no expiry', type: 'number', placeholder: '30', value: '30' },
        { id: 'flags', label: 'Options', type: 'multi', items: [{ id: 'list', label: 'List the current entries afterwards', default: true }] }
      ],
      build: sel => {
        const value = q(sel.value) || 'evil.example';
        const args = ['-ListType ' + sel.type, '-Block', "-Entries '" + value + "'"];
        args.push(sel.days ? '-ExpirationDate (Get-Date).AddDays(' + num(sel.days, 30) + ')' : '-NoExpiration');
        const lines = ['New-TenantAllowBlockListItems ' + args.join(' ')];
        if (sel.flags.has('list')) lines.push('Get-TenantAllowBlockListItems -ListType ' + sel.type + ' -Block | Format-Table Value, Action, ExpirationDate, LastModifiedDateTime -AutoSize');
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'resp-enable-auditing',
      t: 'Turn auditing back on everywhere',
      p: ['Containment', 'Purview', 'Hardening'],
      d: 'Re-enables unified audit ingestion and full mailbox auditing, and lifts the audit age limit so the next incident has data.',
      k: 'enable-organizationcustomization set-adminauditlogconfig unifiedauditlogingestionenabled auditenabled auditlogagelimit turn on auditing',
      more: [
        {
          id: 'steps', label: 'Steps', type: 'multi', items: [
            { id: 'tenant', label: 'Enable unified audit log ingestion', default: true },
            { id: 'mailboxes', label: 'Enable mailbox auditing on every mailbox', default: true },
            { id: 'age', label: 'Set the audit age limit to 180 days', default: true },
            { id: 'bypass', label: 'Remove audit bypass from all accounts', default: true }
          ]
        },
        { id: 'flags', label: 'Options', type: 'multi', items: [{ id: 'whatIf', label: 'Dry run (-WhatIf)', default: true }] }
      ],
      build: sel => {
        const whatIf = sel.flags.has('whatIf') ? ' -WhatIf' : '';
        const lines = [];
        if (sel.steps.has('tenant')) {
          lines.push('Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true' + whatIf);
          lines.push('Set-OrganizationConfig -AuditDisabled $false' + whatIf);
        }
        if (sel.steps.has('mailboxes') || sel.steps.has('age')) {
          lines.push('Get-Mailbox -ResultSize Unlimited | ForEach-Object {');
          const args = ['-Identity $_.UserPrincipalName'];
          if (sel.steps.has('mailboxes')) args.push('-AuditEnabled $true');
          if (sel.steps.has('age')) args.push('-AuditLogAgeLimit 180');
          lines.push('    Set-Mailbox ' + args.join(' ') + whatIf);
          lines.push('}');
        }
        if (sel.steps.has('bypass')) {
          lines.push('Get-MailboxAuditBypassAssociation -ResultSize Unlimited |');
          lines.push('    Where-Object { $_.AuditBypassEnabled } |');
          lines.push('    ForEach-Object { Set-MailboxAuditBypassAssociation -Identity $_.Name -AuditBypassEnabled $false' + whatIf + ' }');
        }
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'resp-evidence-bundle',
      t: 'Collect the full evidence bundle for a user',
      p: ['Collection', 'Containment'],
      d: 'Runs the whole triage set for one account and writes every result to a dated folder: sign-ins, audit records, rules, forwarding, permissions, out of office and MFA.',
      k: 'evidence collection bundle export everything one user triage folder csv preserve report handover',
      req: 'ExchangeOnlineManagement and Microsoft.Graph, both connected.',
      more: [
        { id: 'user', label: 'Account (UPN)', type: 'text', placeholder: 'jdoe@contoso.com' },
        { id: 'days', label: 'Look back (days)', type: 'number', placeholder: '30', value: '30' },
        { id: 'path', label: 'Output folder', type: 'text', placeholder: '.\\IR' },
        {
          id: 'parts', label: 'Collect', type: 'multi', wide: true, items: [
            { id: 'ual', label: 'Unified audit log records', default: true },
            { id: 'signins', label: 'Entra sign-ins', default: true },
            { id: 'rules', label: 'Inbox rules', default: true },
            { id: 'mailbox', label: 'Mailbox and forwarding settings', default: true },
            { id: 'oof', label: 'Out of office configuration', default: true },
            { id: 'perms', label: 'Mailbox permissions', default: true },
            { id: 'mfa', label: 'Registered MFA methods', default: true },
            { id: 'devices', label: 'Mobile devices', default: true },
            { id: 'apps', label: 'Consented applications', default: true }
          ]
        }
      ],
      build: sel => {
        const user = q(sel.user) || 'jdoe@contoso.com';
        const root = q(sel.path) || '.\\IR';
        const lines = [
          "$user = '" + user + "'",
          '$start = (Get-Date).AddDays(-' + num(sel.days, 30) + ')',
          '$end = Get-Date',
          "$folder = Join-Path '" + root + "' (\"$($user.Split('@')[0])-$(Get-Date -Format yyyyMMdd)\")",
          'New-Item -Path $folder -ItemType Directory -Force | Out-Null'
        ];
        if (sel.parts.has('ual')) {
          lines.push('$session = [guid]::NewGuid().ToString()');
          lines.push('$records = @()');
          lines.push('do {');
          lines.push('    $page = Search-UnifiedAuditLog -StartDate $start -EndDate $end -UserIds $user -ResultSize 5000 -SessionId $session -SessionCommand ReturnLargeSet');
          lines.push('    $records += $page');
          lines.push('} while ($page.Count -gt 0)');
          lines.push("$records | Export-Csv -Path (Join-Path $folder 'audit-log.csv') -NoTypeInformation -Encoding UTF8");
        }
        if (sel.parts.has('signins')) {
          lines.push("$cut = $start.ToString('yyyy-MM-ddTHH:mm:ssZ')");
          lines.push('Get-MgAuditLogSignIn -Filter "userPrincipalName eq \'$user\' and createdDateTime ge $cut" -All |');
          lines.push("    Select-Object CreatedDateTime, AppDisplayName, IPAddress, ClientAppUsed, IsInteractive, @{N='Country';E={$_.Location.CountryOrRegion}}, @{N='Error';E={$_.Status.ErrorCode}} |");
          lines.push("    Export-Csv -Path (Join-Path $folder 'signins.csv') -NoTypeInformation -Encoding UTF8");
        }
        if (sel.parts.has('rules')) lines.push("Get-InboxRule -Mailbox $user | ConvertTo-Json -Depth 5 | Out-File (Join-Path $folder 'inbox-rules.json') -Encoding UTF8");
        if (sel.parts.has('mailbox')) lines.push("Get-Mailbox -Identity $user | Select-Object * | Export-Csv -Path (Join-Path $folder 'mailbox.csv') -NoTypeInformation -Encoding UTF8");
        if (sel.parts.has('oof')) lines.push("Get-MailboxAutoReplyConfiguration -Identity $user | ConvertTo-Json | Out-File (Join-Path $folder 'auto-reply.json') -Encoding UTF8");
        if (sel.parts.has('perms')) {
          lines.push("Get-MailboxPermission -Identity $user | Where-Object { -not $_.IsInherited } | Export-Csv -Path (Join-Path $folder 'mailbox-permissions.csv') -NoTypeInformation -Encoding UTF8");
          lines.push("Get-RecipientPermission -Identity $user | Export-Csv -Path (Join-Path $folder 'sendas-permissions.csv') -NoTypeInformation -Encoding UTF8");
        }
        if (sel.parts.has('mfa')) lines.push("Get-MgUserAuthenticationMethod -UserId $user | ConvertTo-Json -Depth 5 | Out-File (Join-Path $folder 'mfa-methods.json') -Encoding UTF8");
        if (sel.parts.has('devices')) lines.push("Get-MobileDevice -Mailbox $user | Export-Csv -Path (Join-Path $folder 'mobile-devices.csv') -NoTypeInformation -Encoding UTF8");
        if (sel.parts.has('apps')) {
          lines.push('$id = (Get-MgUser -UserId $user).Id');
          lines.push('Get-MgOauth2PermissionGrant -Filter "principalId eq \'$id\'" |');
          lines.push("    Export-Csv -Path (Join-Path $folder 'consented-apps.csv') -NoTypeInformation -Encoding UTF8");
        }
        lines.push('Write-Host "Evidence written to $folder"');
        return lines.join('\n');
      }
    },
    {
      kind: 'ps',
      id: 'resp-break-glass-review',
      t: 'Review the emergency access accounts',
      p: ['Containment', 'Identity', 'Hardening'],
      d: 'Checks that the break glass accounts still exist, are excluded from conditional access, and were not used unexpectedly.',
      k: 'break glass emergency access account excluded conditional access global admin last signin review hardening',
      req: GRAPH,
      more: [
        { id: 'filter', label: 'Account name contains', type: 'text', placeholder: 'breakglass', value: 'breakglass' },
        {
          id: 'checks', label: 'Check', type: 'multi', items: [
            { id: 'exists', label: 'The accounts and their roles', default: true },
            { id: 'signins', label: 'Recent sign-ins', default: true },
            { id: 'ca', label: 'Conditional access exclusions', default: true }
          ]
        }
      ],
      build: sel => {
        const name = q(sel.filter) || 'breakglass';
        const lines = ["$pattern = '" + name + "'"];
        if (sel.checks.has('exists')) {
          lines.push('$accounts = Get-MgUser -All -Property Id, UserPrincipalName, AccountEnabled, CreatedDateTime |');
          lines.push('    Where-Object { $_.UserPrincipalName -like "*$pattern*" }');
          lines.push('$accounts | Format-Table UserPrincipalName, AccountEnabled, CreatedDateTime -AutoSize');
        }
        if (sel.checks.has('signins')) {
          lines.push('foreach ($account in $accounts) {');
          lines.push('    Get-MgAuditLogSignIn -Filter "userPrincipalName eq \'$($account.UserPrincipalName)\'" -Top 20 |');
          lines.push('        Select-Object CreatedDateTime, UserPrincipalName, AppDisplayName, IPAddress |');
          lines.push('        Format-Table -AutoSize');
          lines.push('}');
        }
        if (sel.checks.has('ca')) {
          lines.push('Get-MgIdentityConditionalAccessPolicy -All | ForEach-Object {');
          lines.push('    [pscustomobject]@{');
          lines.push('        Policy   = $_.DisplayName');
          lines.push('        State    = $_.State');
          lines.push("        Excluded = ($_.Conditions.Users.ExcludeUsers | ForEach-Object { (Get-MgUser -UserId $_ -ErrorAction SilentlyContinue).UserPrincipalName }) -join ', '");
          lines.push('    }');
          lines.push('} | Where-Object { $_.Excluded -like "*$pattern*" } | Format-Table -AutoSize');
        }
        return lines.join('\n');
      }
    }
  );

  /* --- more incident response specs are appended above this marker --- */

  add(
    {
      kind: 'ps',
      id: 'exo-message-trace-detail',
      t: 'Trace what happened to one message',
      p: ['Exchange Online', 'Phishing'],
      d: 'Follows a single message through transport: the rules that fired, the verdict it got and where it was delivered.',
      k: 'get-messagetracedetailv2 message trace detail events transport rule verdict delivery quarantine one message',
      more: [
        { id: 'id', label: 'Message trace ID', type: 'text', placeholder: '3a1b...guid', hint: 'Taken from the MessageTraceId column of a message trace.' },
        { id: 'recipient', label: 'Recipient address', type: 'text', placeholder: 'victim@contoso.com' },
        { id: 'flags', label: 'Options', type: 'multi', items: [{ id: 'detail', label: 'Show the full event data', default: true }] }
      ],
      build: sel => {
        const id = q(sel.id) || '00000000-0000-0000-0000-000000000000';
        const recipient = q(sel.recipient) || 'victim@contoso.com';
        const lines = [
          "$events = Get-MessageTraceDetailV2 -MessageTraceId '" + id + "' -RecipientAddress '" + recipient + "'"
        ];
        if (sel.flags.has('detail')) lines.push('$events | Select-Object Date, Event, Action, Detail, Data | Format-List');
        else lines.push('$events | Select-Object Date, Event, Action, Detail | Format-Table -AutoSize');
        return lines.join('\n');
      }
    }
  );


  SPECS.forEach(s => SCRIPTS.push(s.kind === 'ual' ? ualEntry(s) : plainEntry(s)));
})();

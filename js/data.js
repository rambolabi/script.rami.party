'use strict';

/* ============================================================================
   Script catalogue for the ScriptsRepo page.

   To add a script, append an object to SCRIPTS:
     { id, title, language, purposes: [], description, requires?, keywords?,
       code: '...' }                       simple entry, code is copied as-is
   For a configurable command, replace `code` with:
       options: [ group, ... ]  and  build(sel) -> command string
   Group types: 'multi' (checkboxes), 'single' (radios), 'text', 'number'.
   Items flagged `default: true` form the initial state.
   The language and purpose filter chips are generated from this data.
   ========================================================================== */

/* Columns for the AD user password report.
   `needs` lists the AD attributes that must be requested via -Properties
   (attributes returned by Get-ADUser by default have an empty list). */
const AD_USER_COLUMNS = [
  // The requested defaults, in output order.
  { id: 'upn', label: 'UserPrincipalName', select: 'UserPrincipalName', needs: [], default: true },
  { id: 'pre2000', label: 'PreWindows2000Name', select: "@{N='PreWindows2000Name';E={$_.SamAccountName}}", needs: [], default: true },
  { id: 'displayName', label: 'DisplayName', select: 'DisplayName', needs: ['DisplayName'], default: true },
  { id: 'created', label: 'AccountCreated', select: "@{N='AccountCreated';E={$_.whenCreated}}", needs: ['whenCreated'], default: true },
  { id: 'pwdLastSet', label: 'PasswordLastSet', select: 'PasswordLastSet', needs: ['PasswordLastSet'], default: true },
  { id: 'pwdNeverExpires', label: 'PasswordNeverExpires', select: 'PasswordNeverExpires', needs: ['PasswordNeverExpires'], default: true },
  { id: 'enabled', label: 'AccountEnabled', select: "@{N='AccountEnabled';E={$_.Enabled}}", needs: [], default: true },
  { id: 'badPwdCount', label: 'badPwdCount', select: 'badPwdCount', needs: ['badPwdCount'], default: true, hint: 'Counted per domain controller, not replicated.' },
  { id: 'homeDir', label: 'homeDirectory', select: 'homeDirectory', needs: ['homeDirectory'], default: true },
  { id: 'lastLogonTs', label: 'LastLogonTimestamp', select: "@{N='LastLogonTimestamp';E={if ($_.lastLogonTimestamp) { [DateTime]::FromFileTime($_.lastLogonTimestamp) }}}", needs: ['lastLogonTimestamp'], default: true, hint: 'Replicated with up to 14 days of lag.' },
  // Useful extras, off by default.
  { id: 'pwdExpiryDate', label: 'PasswordExpiryDate', select: "@{N='PasswordExpiryDate';E={if ($_.'msDS-UserPasswordExpiryTimeComputed' -and $_.'msDS-UserPasswordExpiryTimeComputed' -ne [long]::MaxValue) { [DateTime]::FromFileTime($_.'msDS-UserPasswordExpiryTimeComputed') }}}", needs: ["'msDS-UserPasswordExpiryTimeComputed'"], hint: 'Computed date the current password expires.' },
  { id: 'pwdExpired', label: 'PasswordExpired', select: 'PasswordExpired', needs: ['PasswordExpired'] },
  { id: 'lockedOut', label: 'LockedOut', select: 'LockedOut', needs: ['LockedOut'] },
  { id: 'lastBadPwd', label: 'LastBadPasswordAttempt', select: 'LastBadPasswordAttempt', needs: ['LastBadPasswordAttempt'] },
  { id: 'pwdNotRequired', label: 'PasswordNotRequired', select: 'PasswordNotRequired', needs: ['PasswordNotRequired'], hint: 'Accounts allowed to have a blank password, worth auditing.' },
  { id: 'accountExpires', label: 'AccountExpirationDate', select: 'AccountExpirationDate', needs: ['AccountExpirationDate'] },
  { id: 'email', label: 'EmailAddress', select: 'EmailAddress', needs: ['EmailAddress'] },
  { id: 'department', label: 'Department', select: 'Department', needs: ['Department'] },
  { id: 'jobTitle', label: 'Title', select: 'Title', needs: ['Title'] },
  { id: 'manager', label: 'Manager', select: 'Manager', needs: ['Manager'] },
  { id: 'adDescription', label: 'Description', select: 'Description', needs: ['Description'] },
  { id: 'ou', label: 'OrganizationalUnit', select: "@{N='OrganizationalUnit';E={($_.DistinguishedName -split ',',2)[1]}}", needs: [], hint: 'Parent OU taken from the distinguished name.' },
  { id: 'logonCount', label: 'logonCount', select: 'logonCount', needs: ['logonCount'], hint: 'Counted per domain controller, not replicated.' }
];

function buildAdPasswordReport(sel) {
  const chosen = AD_USER_COLUMNS.filter(c => sel.columns.has(c.id));
  const props = new Set();
  chosen.forEach(c => c.needs.forEach(p => props.add(p)));

  const filters = [];
  if (sel.scope === 'enabled') filters.push('Enabled -eq $true');
  if (sel.scope === 'disabled') filters.push('Enabled -eq $false');
  if (sel.extraFilters.has('neverExpires')) filters.push('PasswordNeverExpires -eq $true');

  const lines = [];
  const days = parseInt(sel.staleDays, 10);
  if (days > 0) {
    lines.push('$oldest = (Get-Date).AddDays(-' + days + ')');
    filters.push('PasswordLastSet -lt $oldest');
  }

  const sortMap = {
    pwdOldest: ['PasswordLastSet', ''],
    pwdNewest: ['PasswordLastSet', ' -Descending'],
    name: ['DisplayName', ''],
    created: ['whenCreated', '']
  };
  const sort = sortMap[sel.sort];
  if (sort) props.add(sort[0]);

  let get = 'Get-ADUser -Filter ' + (filters.length ? "'" + filters.join(' -and ') + "'" : '*');
  const ou = sel.ou.trim();
  if (ou) get += " -SearchBase '" + ou.replace(/'/g, "''") + "'";
  if (props.size) get += ' -Properties ' + Array.from(props).join(', ');

  const stages = [get];
  if (sort) stages.push('Sort-Object ' + sort[0] + sort[1]);
  if (chosen.length) stages.push('Select-Object ' + chosen.map(c => c.select).join(',\n        '));

  const outputMap = {
    table: 'Format-Table -AutoSize',
    grid: "Out-GridView -Title 'AD user password report'",
    csv: 'Export-Csv -Path .\\AD-UserPasswordReport.csv -NoTypeInformation -Encoding UTF8'
  };
  if (outputMap[sel.output]) stages.push(outputMap[sel.output]);

  lines.push(stages.join(' |\n    '));
  return lines.join('\n');
}

function buildPsWebServer(sel) {
  const port = parseInt(sel.port, 10) > 0 ? parseInt(sel.port, 10) : 8123;
  const lines = ['param([int]$Port = ' + port + ')', 'Set-Location $PSScriptRoot'];
  if (sel.onStart.has('openBrowser')) lines.push('Start-Process "http://127.0.0.1:$Port/"');
  lines.push('python -m http.server $Port --bind ' + (sel.bind === 'all' ? '0.0.0.0' : '127.0.0.1'));
  return lines.join('\n');
}

/* Columns for the domain controller list, all returned by default
   by Get-ADDomainController, so no -Properties handling is needed. */
const DC_COLUMNS = [
  { id: 'Name', default: true },
  { id: 'HostName', default: true },
  { id: 'IPv4Address', default: true },
  { id: 'Site', default: true },
  { id: 'IsGlobalCatalog', default: true },
  { id: 'IsReadOnly', default: true, hint: 'True for read-only DCs (RODC).' },
  { id: 'OperatingSystem', default: true },
  { id: 'OperatingSystemVersion' },
  { id: 'Forest' },
  { id: 'Domain' },
  { id: 'Enabled' }
];

function buildDcCount(sel) {
  let get = 'Get-ADDomainController -Filter *';
  const domain = sel.domain.trim();
  if (domain) get += " -Server '" + domain.replace(/'/g, "''") + "'";
  const cols = DC_COLUMNS.filter(c => sel.columns.has(c.id)).map(c => c.id);
  const list = ['Select-Object ' + (cols.length ? cols.join(', ') : '*'), 'Format-Table -AutoSize'];
  if (sel.mode === 'count') return '(' + get + ').Count';
  if (sel.mode === 'list') return [get].concat(list).join(' |\n    ');
  return [
    '$dcs = ' + get,
    '"Domain controllers: $($dcs.Count)"',
    ['$dcs'].concat(list).join(' |\n    ')
  ].join('\n');
}

const SCRIPTS = [
  {
    id: 'ad-user-password-report',
    title: 'AD users with last password change',
    language: 'PowerShell',
    purposes: ['Active Directory', 'Audit', 'Users'],
    description: 'Lists every user in the local Active Directory with the date they last changed their password, plus account health columns. Open it to toggle columns, scope, sorting and output format.',
    requires: 'ActiveDirectory PowerShell module (RSAT) on a domain-joined machine.',
    keywords: 'get-aduser pwdlastset password age stale expiry upn samaccountname enabled report',
    options: [
      {
        id: 'columns', label: 'Columns', type: 'multi', wide: true,
        hint: 'Properties to include, shown in this order. Hover an item for details.',
        items: AD_USER_COLUMNS.map(c => ({ id: c.id, label: c.label, hint: c.hint, default: c.default }))
      },
      {
        id: 'scope', label: 'Account scope', type: 'single', items: [
          { id: 'all', label: 'All accounts', default: true },
          { id: 'enabled', label: 'Enabled only' },
          { id: 'disabled', label: 'Disabled only' }
        ]
      },
      {
        id: 'extraFilters', label: 'Extra filters', type: 'multi', items: [
          { id: 'neverExpires', label: 'Password never expires only' }
        ]
      },
      {
        id: 'staleDays', label: 'Password older than (days)', type: 'number',
        placeholder: 'e.g. 90', hint: 'Leave empty to include every password age.'
      },
      {
        id: 'ou', label: 'Limit to OU (SearchBase)', type: 'text',
        placeholder: 'OU=Staff,DC=contoso,DC=com', hint: 'Optional distinguished name to scope the query.'
      },
      {
        id: 'sort', label: 'Sort', type: 'single', items: [
          { id: 'none', label: 'Directory order', default: true },
          { id: 'pwdOldest', label: 'Oldest password first' },
          { id: 'pwdNewest', label: 'Newest password first' },
          { id: 'name', label: 'Display name' },
          { id: 'created', label: 'Account created' }
        ]
      },
      {
        id: 'output', label: 'Output', type: 'single', items: [
          { id: 'objects', label: 'Plain objects' },
          { id: 'table', label: 'Table (Format-Table)', default: true },
          { id: 'grid', label: 'Grid view (Out-GridView)' },
          { id: 'csv', label: 'CSV file (Export-Csv)' }
        ]
      }
    ],
    build: buildAdPasswordReport
  },
  {
    id: 'ad-locked-out',
    title: 'AD locked-out accounts',
    language: 'PowerShell',
    purposes: ['Active Directory', 'Users', 'Troubleshooting'],
    description: 'Finds every currently locked-out user account in the domain.',
    requires: 'ActiveDirectory PowerShell module (RSAT) on a domain-joined machine.',
    keywords: 'search-adaccount lockout locked unlock account',
    code: 'Search-ADAccount -LockedOut -UsersOnly |\n    Select-Object SamAccountName, UserPrincipalName, LastLogonDate, AccountExpirationDate |\n    Format-Table -AutoSize'
  },
  {
    id: 'ad-dc-count',
    title: 'Count domain controllers',
    language: 'PowerShell',
    purposes: ['Active Directory', 'Audit'],
    description: 'Shows how many domain controllers the domain has. Options add a detail list with site, IP address, global catalog and OS, or target another domain.',
    requires: 'ActiveDirectory PowerShell module (RSAT) on a domain-joined machine.',
    keywords: 'get-addomaincontroller dc count domain controllers site global catalog rodc replica',
    options: [
      {
        id: 'mode', label: 'Output', type: 'single', items: [
          { id: 'count', label: 'Count only', default: true },
          { id: 'list', label: 'Detail list' },
          { id: 'both', label: 'Count + detail list' }
        ]
      },
      {
        id: 'columns', label: 'Detail columns', type: 'multi', wide: true,
        hint: 'Used by the detail list outputs.',
        items: DC_COLUMNS.map(c => ({ id: c.id, label: c.id, hint: c.hint, default: c.default }))
      },
      {
        id: 'domain', label: 'Other domain (optional)', type: 'text',
        placeholder: 'child.contoso.com', hint: 'Queries the current domain when empty.'
      }
    ],
    build: buildDcCount
  },
  {
    id: 'bash-largest-dirs',
    title: 'Largest directories',
    language: 'Bash',
    purposes: ['Files & Disk'],
    description: 'Shows the 20 largest items directly under the current directory, human readable, biggest first.',
    keywords: 'du disk usage size space cleanup full',
    code: 'du -h --max-depth=1 . 2>/dev/null | sort -hr | head -n 20'
  },
  {
    id: 'batch-flush-dns',
    title: 'Flush DNS cache',
    language: 'Batch',
    purposes: ['Network', 'Troubleshooting'],
    description: 'Clears the Windows DNS resolver cache, useful after DNS record changes.',
    keywords: 'ipconfig flushdns resolver cache cmd',
    code: 'ipconfig /flushdns'
  },
  {
    id: 'python-http-server',
    title: 'Quick HTTP server',
    language: 'Python',
    purposes: ['Network', 'Web'],
    description: 'Serves the current directory over HTTP on port 8080, handy for sharing files or testing static pages.',
    keywords: 'http.server simple web share files static',
    code: 'python -m http.server 8080'
  },
  {
    id: 'ps-start-web-server',
    title: 'Start a local web server',
    language: 'PowerShell',
    purposes: ['Network', 'Web'],
    description: 'Save as a .ps1 next to the files to serve: it switches to the script folder, opens the browser and starts a web server there. Pass -Port to override the default.',
    requires: 'Python on PATH for the http.server backend.',
    keywords: 'webserver http serve folder start-process port bind localhost ps1',
    options: [
      {
        id: 'port', label: 'Default port', type: 'number',
        placeholder: '8123', hint: 'Used when the script is run without -Port.'
      },
      {
        id: 'bind', label: 'Listen on', type: 'single', items: [
          { id: 'local', label: 'This machine only (127.0.0.1)', default: true },
          { id: 'all', label: 'All interfaces (LAN access)' }
        ]
      },
      {
        id: 'onStart', label: 'On start', type: 'multi', items: [
          { id: 'openBrowser', label: 'Open the browser', default: true }
        ]
      }
    ],
    build: buildPsWebServer
  },
  {
    id: 'bash-recent-files',
    title: 'Files changed in the last 24 hours',
    language: 'Bash',
    purposes: ['Files & Disk', 'Troubleshooting'],
    description: 'Lists all files modified in the last day, ignoring the .git folder.',
    keywords: 'find mtime modified recent changed',
    code: "find . -type f -mtime -1 -not -path '*/.git/*' | sort"
  }
];

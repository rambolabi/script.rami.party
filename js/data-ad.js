'use strict';

/* ============================================================================
   Active Directory script library.

   Entries are compact specs turned into catalogue items by adSpec().
   Spec keys:
     id, t (title), p (extra purposes), d (description), k (keywords), req
     base   command the pipeline starts with, string or (sel) => string
     cols   selectable columns: 'Name' | '*Name' (on by default) |
            ['Label', 'select expression', ['needed properties'], 'hint', true]
     filt   -Filter toggles:  ['id', 'Label', 'clause' | fn, 'hint', default]
     where  Where-Object toggles, same shape
     sort   ['Label', 'Sort-Object expression'] entries, or a plain property
     tail   { label, items: [['id', 'Label', 'stage' | null, default]] }
            a selected stage replaces the Select-Object stage
     vars   [{ id, label, type, ph, hint, def }] free text or number inputs
     pre    (sel) => line(s) placed above the pipeline
     sb     offer a -SearchBase box        srv  offer a -Server box
     c      add a "Count only" output      props: false  cmdlet has no -Properties
     out: false  no output group           code / build  bypass the factory
   ========================================================================== */

(function () {
  const q = v => String(v).trim().replace(/'/g, "''");
  const val = (v, sel) => (typeof v === 'function' ? v(sel) : v);
  const num = (v, fallback) => (parseInt(v, 10) > 0 ? parseInt(v, 10) : fallback);

  function col(c) {
    if (typeof c === 'string') {
      const def = c.charAt(0) === '*';
      const name = def ? c.slice(1) : c;
      return { id: name, label: name, select: name, needs: [name], default: def };
    }
    return { id: c[0], label: c[0], select: c[1], needs: c[2] || [], hint: c[3], default: !!c[4] };
  }

  function adSpec(s) {
    const cols = (s.cols || []).map(col);
    const sorts = (s.sort || []).map((x, i) => {
      const a = [].concat(x);
      return { id: 's' + i, label: a[0], expr: a[1] || a[0], need: a[2] };
    });
    const fileName = (s.csv || s.id).replace(/[^a-z0-9]+/gi, '-');
    const opts = [];

    if (cols.length) {
      opts.push({
        id: 'columns', label: 'Columns', type: 'multi', wide: true,
        hint: 'Properties to show, in this order. Hover an item for details.',
        items: cols.map(c => ({ id: c.id, label: c.label, hint: c.hint, default: c.default }))
      });
    }
    (s.vars || []).forEach(v => opts.push({
      id: v.id, label: v.label, type: v.type || 'number',
      placeholder: v.ph, hint: v.hint, value: v.def
    }));
    (s.more || []).forEach(g => opts.push(g));
    if (s.filt) {
      opts.push({
        id: 'filters', label: 'Filters', type: 'multi',
        items: s.filt.map(f => ({ id: f[0], label: f[1], hint: f[3], default: !!f[4] }))
      });
    }
    if (s.where) {
      opts.push({
        id: 'wheres', label: s.filt ? 'Extra filters' : 'Filters', type: 'multi',
        items: s.where.map(f => ({ id: f[0], label: f[1], hint: f[3], default: !!f[4] }))
      });
    }
    if (s.tail) {
      opts.push({
        id: 'tail', label: s.tail.label || 'Summary', type: 'single',
        hint: 'A summary replaces the column selection.',
        items: s.tail.items.map(t => ({ id: t[0], label: t[1], default: !!t[3] }))
      });
    }
    if (s.sb) {
      opts.push({
        id: 'ou', label: 'Limit to OU (SearchBase)', type: 'text',
        placeholder: 'OU=Staff,DC=contoso,DC=com', hint: 'Optional distinguished name to scope the query.'
      });
    }
    if (s.srv) {
      opts.push({
        id: 'server', label: 'Domain or DC (-Server)', type: 'text',
        placeholder: 'dc01.contoso.com', hint: 'Optional, targets another domain or a specific DC.'
      });
    }
    if (sorts.length) {
      opts.push({
        id: 'sort', label: 'Sort', type: 'single',
        items: [{ id: 'none', label: 'Directory order', default: true }]
          .concat(sorts.map(x => ({ id: x.id, label: x.label })))
      });
    }
    if (s.out !== false) {
      const items = [
        { id: 'objects', label: 'Plain objects' },
        { id: 'table', label: 'Table (Format-Table)' },
        { id: 'list', label: 'List (Format-List)' },
        { id: 'grid', label: 'Grid view (Out-GridView)' },
        { id: 'csv', label: 'CSV file (Export-Csv)' },
        { id: 'html', label: 'HTML report' }
      ];
      if (s.c) items.splice(1, 0, { id: 'count', label: 'Count only' });
      const chosen = items.find(i => i.id === (s.defOut || 'table')) || items[1];
      chosen.default = true;
      opts.push({ id: 'output', label: 'Output', type: 'single', items: items });
    }

    function outputStage(sel) {
      switch (sel.output) {
        case 'table': return 'Format-Table -AutoSize';
        case 'list': return 'Format-List';
        case 'grid': return "Out-GridView -Title '" + q(s.t) + "'";
        case 'csv': return 'Export-Csv -Path .\\' + fileName + '.csv -NoTypeInformation -Encoding UTF8';
        case 'html': return "ConvertTo-Html -Title '" + q(s.t) + "' | Out-File .\\" + fileName + '.html -Encoding UTF8';
        default: return null;
      }
    }

    function build(sel) {
      const lines = [];
      if (s.pre) [].concat(s.pre(sel)).forEach(l => { if (l) lines.push(l); });

      const props = new Set();
      const picks = [];
      cols.forEach(c => {
        if (sel.columns && sel.columns.has(c.id)) {
          picks.push(c.select);
          c.needs.forEach(n => props.add(n));
        }
      });

      const filters = [];
      (s.filt || []).forEach(f => {
        if (sel.filters.has(f[0])) { const v = val(f[2], sel); if (v) filters.push(v); }
      });
      const wheres = [];
      (s.where || []).forEach(f => {
        if (sel.wheres.has(f[0])) { const v = val(f[2], sel); if (v) wheres.push(v); }
      });

      let base = val(s.base, sel);
      if (filters.length) {
        // Inner quotes are doubled so the AD filter parser still sees them.
        const clause = " -Filter '" + filters.join(' -and ').replace(/'/g, "''") + "'";
        base = base.indexOf('-Filter *') >= 0 ? base.replace('-Filter *', clause.slice(1)) : base + clause;
      }
      if (s.sb && sel.ou.trim()) base += " -SearchBase '" + q(sel.ou) + "'";
      if (s.srv && sel.server.trim()) base += " -Server '" + q(sel.server) + "'";

      const sorted = sorts.find(x => x.id === sel.sort);
      if (sorted && sorted.need) props.add(sorted.need);
      if (s.props !== false && props.size) base += ' -Properties ' + Array.from(props).join(', ');

      const stages = [base];
      if (wheres.length) stages.push('Where-Object { ' + wheres.join(' -and ') + ' }');
      if (sel.output === 'count') {
        lines.push('@(' + stages.join(' |\n    ') + ').Count');
        return lines.join('\n');
      }
      if (sorted) stages.push('Sort-Object ' + sorted.expr);

      const tail = s.tail && s.tail.items.find(t => t[0] === sel.tail);
      if (tail && tail[2]) stages.push(tail[2]);
      else if (picks.length) stages.push('Select-Object ' + picks.join(',\n        '));

      const out = s.out === false ? null : outputStage(sel);
      if (out) stages.push(out);

      lines.push(stages.join(' |\n    '));
      return lines.join('\n');
    }

    const entry = {
      id: s.id,
      title: s.t,
      language: 'PowerShell',
      purposes: ['Active Directory'].concat(s.p || []),
      description: s.d,
      requires: s.req || 'ActiveDirectory PowerShell module (RSAT) on a domain-joined machine.',
      keywords: s.k || ''
    };
    if (s.code) entry.code = s.code;
    else if (s.build) { entry.options = s.options || s.more || []; entry.build = s.build; }
    else { entry.options = opts; entry.build = build; }
    return entry;
  }

  const DAYS = (id, label, def, hint) => ({ id: id || 'days', label: label || 'Age in days', type: 'number', ph: String(def), hint: hint, def: String(def) });
  const CUT = (field, def) => sel => '$cut = (Get-Date).AddDays(-' + num(sel[field || 'days'], def) + ')';

  const SPECS = [];

  /* ---------------------------------------------------------------- users */

  SPECS.push(
    {
      id: 'ad-users-inactive',
      t: 'Inactive user accounts',
      p: ['Users', 'Cleanup', 'Audit'],
      d: 'Finds user accounts that have not signed in for a number of days, the usual starting point for account cleanup.',
      k: 'stale inactive lastlogondate dormant unused cleanup offboarding',
      base: 'Get-ADUser -Filter *',
      vars: [DAYS('days', 'Inactive for at least (days)', 90)],
      pre: CUT('days', 90),
      cols: ['*Name', '*SamAccountName', '*LastLogonDate', '*Enabled', 'UserPrincipalName', 'PasswordLastSet', 'whenCreated', 'Description', '*DistinguishedName'],
      filt: [['enabled', 'Enabled accounts only', 'Enabled -eq $true', null, true]],
      where: [
        ['stale', 'Last logon older than the day count', '$_.LastLogonDate -lt $cut', null, true],
        ['never', 'Include accounts that never signed in', '-not $_.LastLogonDate']
      ],
      sort: [['Oldest logon first', 'LastLogonDate'], ['Name', 'Name']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-users-disabled',
      t: 'Disabled user accounts',
      p: ['Users', 'Cleanup'],
      d: 'Lists every disabled user account with the date it was disabled last modified, handy before archiving or deleting.',
      k: 'disabled inactive blocked offboarded leavers',
      base: 'Get-ADUser -Filter *',
      cols: ['*Name', '*SamAccountName', '*whenChanged', 'UserPrincipalName', 'LastLogonDate', 'Description', 'whenCreated', '*DistinguishedName'],
      filt: [['disabled', 'Disabled only', 'Enabled -eq $false', null, true]],
      sort: [['Last changed', 'whenChanged -Descending'], ['Name', 'Name']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-users-never-logged-on',
      t: 'Users that never signed in',
      p: ['Users', 'Cleanup', 'Security'],
      d: 'Accounts that were created but never used, often left over from onboarding or test accounts.',
      k: 'never logged on unused lastlogon empty new accounts',
      base: 'Get-ADUser -Filter *',
      cols: ['*Name', '*SamAccountName', '*whenCreated', '*Enabled', 'UserPrincipalName', 'Description', 'PasswordLastSet', '*DistinguishedName'],
      filt: [['enabled', 'Enabled accounts only', 'Enabled -eq $true']],
      where: [['never', 'Never signed in', '-not $_.LastLogonDate', null, true]],
      sort: [['Oldest first', 'whenCreated'], ['Name', 'Name']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-users-recently-created',
      t: 'Recently created users',
      p: ['Users', 'Audit', 'Security'],
      d: 'Shows user accounts created in the last few days, a quick check for unexpected account creation.',
      k: 'new accounts whencreated onboarding audit recent',
      base: 'Get-ADUser -Filter *',
      vars: [DAYS('days', 'Created in the last (days)', 7)],
      pre: CUT('days', 7),
      cols: ['*Name', '*SamAccountName', '*whenCreated', '*Enabled', 'UserPrincipalName', 'Description', '*DistinguishedName'],
      where: [['recent', 'Created after the cut-off date', '$_.whenCreated -ge $cut', null, true]],
      sort: [['Newest first', 'whenCreated -Descending']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-users-password-never-expires',
      t: 'Passwords set to never expire',
      p: ['Users', 'Security', 'Audit'],
      d: 'Accounts whose password never expires, one of the most common audit findings.',
      k: 'passwordneverexpires dont expire policy exception audit',
      base: 'Get-ADUser -Filter *',
      cols: ['*Name', '*SamAccountName', '*PasswordLastSet', '*Enabled', 'UserPrincipalName', 'LastLogonDate', 'Description', '*DistinguishedName'],
      filt: [
        ['never', 'Password never expires', 'PasswordNeverExpires -eq $true', null, true],
        ['enabled', 'Enabled accounts only', 'Enabled -eq $true', null, true]
      ],
      sort: [['Oldest password first', 'PasswordLastSet']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-users-password-expiring-soon',
      t: 'Passwords expiring soon',
      p: ['Users', 'Reporting'],
      d: 'Lists users whose password expires within the next few days, ready to feed a reminder mail.',
      k: 'expiry expiring msds-userpasswordexpirytimecomputed reminder notify',
      base: 'Get-ADUser -Filter *',
      vars: [DAYS('days', 'Expiring within (days)', 14)],
      pre: sel => '$cut = (Get-Date).AddDays(' + num(sel.days, 14) + ')',
      cols: [
        '*Name', '*SamAccountName', '*EmailAddress',
        ['PasswordExpiry', "@{N='PasswordExpiry';E={[DateTime]::FromFileTime($_.'msDS-UserPasswordExpiryTimeComputed')}}", ["'msDS-UserPasswordExpiryTimeComputed'"], 'Computed expiry date of the current password.', true],
        'PasswordLastSet', 'UserPrincipalName', 'LastLogonDate'
      ],
      filt: [
        ['enabled', 'Enabled accounts only', 'Enabled -eq $true', null, true],
        ['expires', 'Skip never-expiring passwords', 'PasswordNeverExpires -eq $false', null, true]
      ],
      where: [['soon', 'Expires before the cut-off date', "$_.'msDS-UserPasswordExpiryTimeComputed' -lt $cut.ToFileTime()", null, true]],
      sort: [['Soonest first', "{$_.'msDS-UserPasswordExpiryTimeComputed'}"]],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-users-password-not-required',
      t: 'Accounts that allow a blank password',
      p: ['Users', 'Security', 'Audit'],
      d: 'Finds accounts with PASSWD_NOTREQD set, which lets them keep an empty password.',
      k: 'passwordnotrequired blank empty passwd_notreqd weak security',
      base: 'Get-ADUser -Filter *',
      cols: ['*Name', '*SamAccountName', '*PasswordNotRequired', '*Enabled', 'PasswordLastSet', 'LastLogonDate', '*DistinguishedName'],
      filt: [
        ['notreq', 'Password not required', 'PasswordNotRequired -eq $true', null, true],
        ['enabled', 'Enabled accounts only', 'Enabled -eq $true']
      ],
      sort: [['Name', 'Name']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-users-reversible-encryption',
      t: 'Reversible password encryption',
      p: ['Users', 'Security', 'Audit'],
      d: 'Accounts storing their password with reversible encryption, effectively plain text at rest.',
      k: 'reversible encryption cleartext allowreversiblepasswordencryption cis benchmark',
      base: 'Get-ADUser -Filter *',
      cols: ['*Name', '*SamAccountName', '*AllowReversiblePasswordEncryption', '*Enabled', 'PasswordLastSet', '*DistinguishedName'],
      filt: [['rev', 'Reversible encryption enabled', 'AllowReversiblePasswordEncryption -eq $true', null, true]],
      sort: [['Name', 'Name']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-users-smartcard-required',
      t: 'Smart card required accounts',
      p: ['Users', 'Security'],
      d: 'Shows which accounts must sign in with a smart card, including when their NTLM hash was last rotated.',
      k: 'smartcardlogonrequired smart card mfa certificate kerberos',
      base: 'Get-ADUser -Filter *',
      cols: ['*Name', '*SamAccountName', '*SmartcardLogonRequired', '*PasswordLastSet', '*Enabled', 'LastLogonDate', 'DistinguishedName'],
      filt: [
        ['sc', 'Smart card required', 'SmartcardLogonRequired -eq $true', null, true],
        ['enabled', 'Enabled accounts only', 'Enabled -eq $true']
      ],
      sort: [['Oldest hash rotation first', 'PasswordLastSet']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-users-account-expiring',
      t: 'Accounts expiring or expired',
      p: ['Users', 'Reporting', 'Cleanup'],
      d: 'Contractor and temporary accounts with an expiry date, filtered on a window you choose.',
      k: 'accountexpirationdate contractor temporary expiry expired end date',
      base: 'Get-ADUser -Filter *',
      vars: [DAYS('days', 'Window in days', 30, 'Looks ahead this many days.')],
      pre: sel => '$cut = (Get-Date).AddDays(' + num(sel.days, 30) + ')',
      cols: ['*Name', '*SamAccountName', '*AccountExpirationDate', '*Enabled', 'Manager', 'Description', 'LastLogonDate', '*DistinguishedName'],
      where: [
        ['set', 'Has an expiry date', '$_.AccountExpirationDate', null, true],
        ['window', 'Expires before the cut-off date', '$_.AccountExpirationDate -lt $cut', null, true],
        ['past', 'Already expired only', '$_.AccountExpirationDate -lt (Get-Date)']
      ],
      sort: [['Soonest first', 'AccountExpirationDate']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-users-bad-password-attempts',
      t: 'Accounts with failed password attempts',
      p: ['Users', 'Security', 'Troubleshooting'],
      d: 'Users with a high bad password count on the queried DC, useful when hunting a lockout or spray.',
      k: 'badpwdcount lockout brute force spray lastbadpasswordattempt failed logon',
      req: 'ActiveDirectory module. badPwdCount is per DC, so query each DC or the PDC emulator.',
      base: 'Get-ADUser -Filter *',
      vars: [DAYS('min', 'Minimum bad password count', 3)],
      pre: () => null,
      cols: ['*Name', '*SamAccountName', '*badPwdCount', '*LastBadPasswordAttempt', '*LockedOut', 'Enabled', 'PasswordLastSet', 'DistinguishedName'],
      filt: [['enabled', 'Enabled accounts only', 'Enabled -eq $true', null, true]],
      where: [['count', 'Above the minimum bad password count', sel => '$_.badPwdCount -ge ' + num(sel.min, 3), null, true]],
      sort: [['Most attempts first', 'badPwdCount -Descending']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-users-locked-out-detail',
      t: 'Locked out accounts with detail',
      p: ['Users', 'Troubleshooting', 'Security'],
      d: 'Every currently locked out account with the lockout time and the DC that holds the lockout.',
      k: 'lockedout lockouttime unlock search-adaccount helpdesk',
      base: 'Search-ADAccount -LockedOut -UsersOnly',
      props: false,
      cols: ['*Name', '*SamAccountName', '*LockedOut', '*LastLogonDate', 'UserPrincipalName', 'DistinguishedName'],
      srv: 1, c: 1,
      sort: [['Name', 'Name']]
    },
    {
      id: 'ad-user-unlock',
      t: 'Unlock a user account',
      p: ['Users', 'Troubleshooting'],
      d: 'Unlocks one account, optionally on every domain controller so the helpdesk does not wait for replication.',
      k: 'unlock-adaccount locked helpdesk reset lockout',
      options: [
        { id: 'user', label: 'User (SamAccountName or UPN)', type: 'text', placeholder: 'jdoe', hint: 'The account to unlock.' },
        {
          id: 'scope', label: 'Where', type: 'single', items: [
            { id: 'default', label: 'Nearest DC', default: true },
            { id: 'pdc', label: 'PDC emulator' },
            { id: 'all', label: 'Every domain controller' }
          ]
        },
        { id: 'extra', label: 'Also', type: 'multi', items: [{ id: 'show', label: 'Show the result afterwards', default: true }] }
      ],
      build: sel => {
        const user = q(sel.user) || 'jdoe';
        const lines = [];
        if (sel.scope === 'pdc') {
          lines.push('$pdc = (Get-ADDomain).PDCEmulator');
          lines.push("Unlock-ADAccount -Identity '" + user + "' -Server $pdc");
        } else if (sel.scope === 'all') {
          lines.push('Get-ADDomainController -Filter * | ForEach-Object {');
          lines.push("    Unlock-ADAccount -Identity '" + user + "' -Server $_.HostName -ErrorAction SilentlyContinue");
          lines.push('}');
        } else {
          lines.push("Unlock-ADAccount -Identity '" + user + "'");
        }
        if (sel.extra.has('show')) {
          lines.push("Get-ADUser -Identity '" + user + "' -Properties LockedOut, badPwdCount, LastBadPasswordAttempt |");
          lines.push('    Format-List Name, LockedOut, badPwdCount, LastBadPasswordAttempt');
        }
        return lines.join('\n');
      }
    },
    {
      id: 'ad-user-reset-password',
      t: 'Reset a user password',
      p: ['Users', 'Security'],
      d: 'Sets a new password for one account, with the usual follow-up switches for change at next logon and unlocking.',
      k: 'set-adaccountpassword reset password change next logon enable unlock',
      options: [
        { id: 'user', label: 'User (SamAccountName or UPN)', type: 'text', placeholder: 'jdoe' },
        {
          id: 'after', label: 'After the reset', type: 'multi', items: [
            { id: 'mustChange', label: 'Must change at next logon', default: true },
            { id: 'unlock', label: 'Unlock the account', default: true },
            { id: 'enable', label: 'Enable the account' }
          ]
        }
      ],
      build: sel => {
        const user = q(sel.user) || 'jdoe';
        const lines = [
          "$pw = Read-Host 'New password' -AsSecureString",
          "Set-ADAccountPassword -Identity '" + user + "' -Reset -NewPassword $pw"
        ];
        if (sel.after.has('mustChange')) lines.push("Set-ADUser -Identity '" + user + "' -ChangePasswordAtLogon $true");
        if (sel.after.has('unlock')) lines.push("Unlock-ADAccount -Identity '" + user + "'");
        if (sel.after.has('enable')) lines.push("Enable-ADAccount -Identity '" + user + "'");
        return lines.join('\n');
      }
    },
    {
      id: 'ad-user-group-membership',
      t: 'Groups of one user',
      p: ['Users', 'Groups', 'Audit'],
      d: 'Lists the groups a single user belongs to, directly or through nesting.',
      k: 'memberof get-adprincipalgroupmembership nested recursive membership token',
      options: [
        { id: 'user', label: 'User (SamAccountName or UPN)', type: 'text', placeholder: 'jdoe' },
        {
          id: 'depth', label: 'Membership', type: 'single', items: [
            { id: 'direct', label: 'Direct groups only', default: true },
            { id: 'nested', label: 'Including nested groups' }
          ]
        },
        {
          id: 'output', label: 'Output', type: 'single', items: [
            { id: 'table', label: 'Table (Format-Table)', default: true },
            { id: 'names', label: 'Names only' },
            { id: 'csv', label: 'CSV file (Export-Csv)' }
          ]
        }
      ],
      build: sel => {
        const user = q(sel.user) || 'jdoe';
        const lines = [];
        if (sel.depth === 'nested') {
          lines.push("$dn = (Get-ADUser -Identity '" + user + "').DistinguishedName");
          lines.push('$groups = Get-ADGroup -LDAPFilter "(member:1.2.840.113556.1.4.1941:=$dn)"');
        } else {
          lines.push("$groups = Get-ADPrincipalGroupMembership -Identity '" + user + "'");
        }
        if (sel.output === 'names') lines.push('$groups | Select-Object -ExpandProperty Name | Sort-Object');
        else if (sel.output === 'csv') lines.push('$groups | Select-Object Name, GroupCategory, GroupScope, DistinguishedName |\n    Export-Csv -Path .\\UserGroups.csv -NoTypeInformation -Encoding UTF8');
        else lines.push('$groups | Select-Object Name, GroupCategory, GroupScope, DistinguishedName |\n    Sort-Object Name |\n    Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      id: 'ad-user-resultant-password-policy',
      t: 'Effective password policy for a user',
      p: ['Users', 'Security'],
      d: 'Shows which password policy actually applies to an account, fine grained policy or the domain default.',
      k: 'get-aduserresultantpasswordpolicy fine grained psofine granular default domain policy',
      options: [
        { id: 'user', label: 'User (SamAccountName or UPN)', type: 'text', placeholder: 'jdoe' },
        {
          id: 'fallback', label: 'When no fine grained policy applies', type: 'multi',
          items: [{ id: 'domain', label: 'Fall back to the domain policy', default: true }]
        }
      ],
      build: sel => {
        const user = q(sel.user) || 'jdoe';
        const lines = ["$policy = Get-ADUserResultantPasswordPolicy -Identity '" + user + "'"];
        if (sel.fallback.has('domain')) lines.push('if (-not $policy) { $policy = Get-ADDefaultDomainPasswordPolicy }');
        lines.push('$policy | Format-List Name, MinPasswordLength, PasswordHistoryCount, MaxPasswordAge, MinPasswordAge, LockoutThreshold, LockoutDuration, ComplexityEnabled');
        return lines.join('\n');
      }
    },
    {
      id: 'ad-user-last-logon-all-dcs',
      t: 'True last logon across all DCs',
      p: ['Users', 'Audit', 'Troubleshooting'],
      d: 'lastLogon is not replicated, so this queries every domain controller and keeps the newest value per user.',
      k: 'lastlogon lastlogontimestamp replication accurate real per dc',
      options: [
        { id: 'user', label: 'User (leave empty for all users)', type: 'text', placeholder: 'jdoe' },
        {
          id: 'output', label: 'Output', type: 'single', items: [
            { id: 'table', label: 'Table (Format-Table)', default: true },
            { id: 'csv', label: 'CSV file (Export-Csv)' },
            { id: 'grid', label: 'Grid view (Out-GridView)' }
          ]
        }
      ],
      build: sel => {
        const user = q(sel.user);
        const lines = [
          '$results = @{}',
          'Get-ADDomainController -Filter * | ForEach-Object {',
          '    Get-ADUser -Filter ' + (user ? "\"SamAccountName -eq '" + user + "'\"" : '*') + ' -Server $_.HostName -Properties lastLogon | ForEach-Object {',
          '        $stamp = if ($_.lastLogon) { [DateTime]::FromFileTime($_.lastLogon) } else { $null }',
          '        if (-not $results[$_.SamAccountName] -or $stamp -gt $results[$_.SamAccountName]) {',
          '            $results[$_.SamAccountName] = $stamp',
          '        }',
          '    }',
          '}',
          "$report = $results.GetEnumerator() | Select-Object @{N='SamAccountName';E={$_.Key}}, @{N='LastLogon';E={$_.Value}}"
        ];
        if (sel.output === 'csv') lines.push('$report | Sort-Object LastLogon | Export-Csv -Path .\\LastLogon.csv -NoTypeInformation -Encoding UTF8');
        else if (sel.output === 'grid') lines.push("$report | Sort-Object LastLogon | Out-GridView -Title 'True last logon'");
        else lines.push('$report | Sort-Object LastLogon | Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      id: 'ad-users-admincount',
      t: 'Accounts flagged with adminCount',
      p: ['Users', 'Security', 'Audit'],
      d: 'adminCount=1 marks accounts that are or were privileged, and they keep the flag after being removed from the group.',
      k: 'admincount adminsdholder privileged orphaned protected groups sdprop',
      base: 'Get-ADUser -Filter *',
      cols: ['*Name', '*SamAccountName', '*adminCount', '*Enabled', 'MemberOf', 'LastLogonDate', 'PasswordLastSet', '*DistinguishedName'],
      filt: [['flag', 'adminCount is set', 'adminCount -eq 1', null, true]],
      sort: [['Name', 'Name']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-users-with-spn',
      t: 'Service accounts with an SPN (kerberoastable)',
      p: ['Users', 'Security', 'Audit'],
      d: 'User accounts carrying a service principal name, the accounts a kerberoasting attack targets.',
      k: 'kerberoast serviceprincipalname spn service account password age attack surface',
      base: 'Get-ADUser -Filter *',
      cols: ['*Name', '*SamAccountName', '*ServicePrincipalName', '*PasswordLastSet', '*Enabled',
        ['PasswordAgeDays', "@{N='PasswordAgeDays';E={if ($_.PasswordLastSet) { [int]((Get-Date) - $_.PasswordLastSet).TotalDays }}}", ['PasswordLastSet'], 'Older passwords are easier to crack offline.', true],
        'TrustedForDelegation', 'DistinguishedName'],
      filt: [
        ['spn', 'Has a service principal name', "ServicePrincipalName -like '*'", null, true],
        ['enabled', 'Enabled accounts only', 'Enabled -eq $true', null, true]
      ],
      sort: [['Oldest password first', 'PasswordLastSet']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-users-no-preauth',
      t: 'Kerberos pre-authentication not required',
      p: ['Users', 'Security', 'Audit'],
      d: 'Accounts vulnerable to AS-REP roasting because they do not require Kerberos pre-authentication.',
      k: 'asrep roasting preauth doesnotrequirepreauth kerberos attack',
      base: 'Get-ADUser -Filter *',
      cols: ['*Name', '*SamAccountName', '*DoesNotRequirePreAuth', '*Enabled', 'PasswordLastSet', 'LastLogonDate', '*DistinguishedName'],
      filt: [['preauth', 'Pre-authentication not required', 'DoesNotRequirePreAuth -eq $true', null, true]],
      sort: [['Name', 'Name']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-users-sid-history',
      t: 'Accounts carrying SID history',
      p: ['Users', 'Security', 'Cleanup'],
      d: 'SID history is normal right after a migration and a privilege escalation route if it is left behind.',
      k: 'sidhistory migration admt injection cleanup escalation',
      base: 'Get-ADUser -Filter *',
      cols: ['*Name', '*SamAccountName', '*SIDHistory', '*Enabled', 'whenCreated', '*DistinguishedName'],
      filt: [['sid', 'Has SID history', "SIDHistory -like '*'", null, true]],
      sort: [['Name', 'Name']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-users-missing-attributes',
      t: 'Users with missing attributes',
      p: ['Users', 'Reporting', 'Cleanup'],
      d: 'Finds accounts where common directory fields are empty, so the data can be fixed before it feeds other systems.',
      k: 'empty blank missing mail manager department title data quality hygiene',
      base: 'Get-ADUser -Filter *',
      cols: ['*Name', '*SamAccountName', '*EmailAddress', '*Manager', '*Department', '*Title', 'Office', 'TelephoneNumber', '*DistinguishedName'],
      filt: [['enabled', 'Enabled accounts only', 'Enabled -eq $true', null, true]],
      where: [
        ['mail', 'No email address', '-not $_.EmailAddress', null, true],
        ['manager', 'No manager', '-not $_.Manager'],
        ['dept', 'No department', '-not $_.Department'],
        ['title', 'No job title', '-not $_.Title']
      ],
      sort: [['Name', 'Name']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-users-recently-modified',
      t: 'Recently modified users',
      p: ['Users', 'Audit', 'Security'],
      d: 'Accounts changed in the last few days, a fast way to spot unexpected edits in the directory.',
      k: 'whenchanged modified changed audit recent tamper',
      base: 'Get-ADUser -Filter *',
      vars: [DAYS('days', 'Changed in the last (days)', 7)],
      pre: CUT('days', 7),
      cols: ['*Name', '*SamAccountName', '*whenChanged', '*Enabled', 'whenCreated', 'PasswordLastSet', 'Description', '*DistinguishedName'],
      where: [['recent', 'Changed after the cut-off date', '$_.whenChanged -ge $cut', null, true]],
      sort: [['Newest first', 'whenChanged -Descending']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-users-home-directories',
      t: 'Home directory and profile paths',
      p: ['Users', 'Reporting', 'Files & Disk'],
      d: 'Reports the home folder, drive letter, profile and logon script per user before a file server migration.',
      k: 'homedirectory homedrive profilepath scriptpath logon script migration file server',
      base: 'Get-ADUser -Filter *',
      cols: ['*Name', '*SamAccountName', '*HomeDirectory', '*HomeDrive', '*ProfilePath', '*ScriptPath', 'Enabled', 'LastLogonDate', 'DistinguishedName'],
      filt: [['enabled', 'Enabled accounts only', 'Enabled -eq $true', null, true]],
      where: [['has', 'Only accounts with a home directory', '$_.HomeDirectory']],
      sort: [['Name', 'Name'], ['Home directory', 'HomeDirectory']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-users-manager-report',
      t: 'Users by manager',
      p: ['Users', 'Reporting'],
      d: 'Builds an org style report of users with the display name of their manager instead of the raw distinguished name.',
      k: 'manager org chart reports-to hierarchy hr export',
      base: 'Get-ADUser -Filter *',
      cols: [
        '*Name', '*SamAccountName',
        ['ManagerName', "@{N='ManagerName';E={if ($_.Manager) { (Get-ADUser $_.Manager).Name }}}", ['Manager'], 'Resolves the manager DN to a display name.', true],
        '*Department', '*Title', 'EmailAddress', 'Office', 'Enabled'
      ],
      filt: [['enabled', 'Enabled accounts only', 'Enabled -eq $true', null, true]],
      sort: [['Department', 'Department'], ['Name', 'Name']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-users-per-ou-count',
      t: 'User count per OU',
      p: ['Users', 'Reporting'],
      d: 'Counts users per organisational unit, useful for sizing a migration or checking where accounts live.',
      k: 'group-object ou count distribution per organizational unit inventory',
      base: 'Get-ADUser -Filter *',
      cols: [
        ['OU', "@{N='OU';E={($_.DistinguishedName -split ',',2)[1]}}", [], 'Parent OU taken from the distinguished name.', true],
        '*Name', '*SamAccountName', 'Enabled'
      ],
      filt: [['enabled', 'Enabled accounts only', 'Enabled -eq $true']],
      tail: {
        label: 'Summary', items: [
          ['none', 'No summary, list the columns'],
          ['count', 'Count per OU', "Group-Object { ($_.DistinguishedName -split ',',2)[1] } -NoElement |\n    Sort-Object Count -Descending", true]
        ]
      },
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-users-bulk-create-csv',
      t: 'Bulk create users from CSV',
      p: ['Users', 'Bulk changes'],
      d: 'Reads a CSV and creates one account per row, with the switches most onboarding scripts need.',
      k: 'new-aduser import-csv bulk create onboarding provisioning mass',
      options: [
        { id: 'csv', label: 'CSV path', type: 'text', placeholder: '.\\newusers.csv', hint: 'Columns: Name, SamAccountName, GivenName, Surname, Department.' },
        { id: 'ou', label: 'Target OU', type: 'text', placeholder: 'OU=Staff,DC=contoso,DC=com' },
        { id: 'upnSuffix', label: 'UPN suffix', type: 'text', placeholder: 'contoso.com' },
        {
          id: 'flags', label: 'Account settings', type: 'multi', items: [
            { id: 'enabled', label: 'Enable the account', default: true },
            { id: 'mustChange', label: 'Must change password at next logon', default: true },
            { id: 'whatIf', label: 'Dry run (-WhatIf)', default: true }
          ]
        }
      ],
      build: sel => {
        const path = q(sel.csv) || '.\\newusers.csv';
        const ou = q(sel.ou) || 'OU=Staff,DC=contoso,DC=com';
        const suffix = q(sel.upnSuffix) || 'contoso.com';
        const args = [
          "-Name $_.Name",
          "-SamAccountName $_.SamAccountName",
          "-UserPrincipalName \"$($_.SamAccountName)@" + suffix + "\"",
          '-GivenName $_.GivenName',
          '-Surname $_.Surname',
          '-Department $_.Department',
          "-Path '" + ou + "'",
          '-AccountPassword $pw'
        ];
        if (sel.flags.has('enabled')) args.push('-Enabled $true');
        if (sel.flags.has('mustChange')) args.push('-ChangePasswordAtLogon $true');
        if (sel.flags.has('whatIf')) args.push('-WhatIf');
        return [
          "$pw = Read-Host 'Initial password' -AsSecureString",
          "Import-Csv -Path '" + path + "' | ForEach-Object {",
          '    New-ADUser ' + args.join(' `\n        '),
          '}'
        ].join('\n');
      }
    },
    {
      id: 'ad-users-bulk-disable-stale',
      t: 'Bulk disable and move stale users',
      p: ['Users', 'Cleanup', 'Bulk changes'],
      d: 'Disables accounts that passed the inactivity threshold, with an optional move to a holding OU and a dry run switch.',
      k: 'disable-adaccount move-adobject stale cleanup offboarding whatif bulk',
      options: [
        { id: 'days', label: 'Inactive for at least (days)', type: 'number', placeholder: '180', value: '180' },
        { id: 'ou', label: 'Move to OU (optional)', type: 'text', placeholder: 'OU=Disabled,DC=contoso,DC=com' },
        {
          id: 'steps', label: 'Actions', type: 'multi', items: [
            { id: 'disable', label: 'Disable the account', default: true },
            { id: 'describe', label: 'Stamp the description with the date', default: true },
            { id: 'log', label: 'Write a CSV log first', default: true },
            { id: 'whatIf', label: 'Dry run (-WhatIf)', default: true }
          ]
        }
      ],
      build: sel => {
        const days = num(sel.days, 180);
        const whatIf = sel.steps.has('whatIf') ? ' -WhatIf' : '';
        const lines = [
          '$cut = (Get-Date).AddDays(-' + days + ')',
          "$stale = Get-ADUser -Filter 'Enabled -eq $true' -Properties LastLogonDate, Description |",
          '    Where-Object { $_.LastLogonDate -lt $cut }'
        ];
        if (sel.steps.has('log')) lines.push('$stale | Select-Object Name, SamAccountName, LastLogonDate, DistinguishedName |\n    Export-Csv -Path .\\StaleUsers.csv -NoTypeInformation -Encoding UTF8');
        lines.push('$stale | ForEach-Object {');
        if (sel.steps.has('describe')) lines.push('    Set-ADUser -Identity $_ -Description "Disabled $(Get-Date -Format yyyy-MM-dd), inactive"' + whatIf);
        if (sel.steps.has('disable')) lines.push('    Disable-ADAccount -Identity $_' + whatIf);
        if (q(sel.ou)) lines.push("    Move-ADObject -Identity $_ -TargetPath '" + q(sel.ou) + "'" + whatIf);
        lines.push('}');
        return lines.join('\n');
      }
    },
    {
      id: 'ad-deleted-objects',
      t: 'Deleted objects and restore',
      p: ['Cleanup', 'Troubleshooting', 'Users'],
      d: 'Browses the AD Recycle Bin and shows the one liner that restores an object.',
      k: 'recycle bin deleted restore-adobject tombstone undelete recover',
      req: 'ActiveDirectory module and an enabled AD Recycle Bin.',
      options: [
        { id: 'name', label: 'Name contains (optional)', type: 'text', placeholder: 'jdoe' },
        { id: 'days', label: 'Deleted in the last (days)', type: 'number', placeholder: '30', value: '30' },
        {
          id: 'mode', label: 'Action', type: 'single', items: [
            { id: 'list', label: 'List deleted objects', default: true },
            { id: 'restore', label: 'Restore the matches' }
          ]
        }
      ],
      build: sel => {
        const name = q(sel.name);
        const lines = ['$cut = (Get-Date).AddDays(-' + num(sel.days, 30) + ')'];
        let get = 'Get-ADObject -IncludeDeletedObjects -Filter ' +
          (name ? "\"isDeleted -eq $true -and Name -like '*" + name + "*'\"" : "'isDeleted -eq $true'") +
          ' -Properties whenChanged, lastKnownParent, objectClass';
        lines.push('$deleted = ' + get + ' |\n    Where-Object { $_.whenChanged -ge $cut }');
        if (sel.mode === 'restore') lines.push('$deleted | Restore-ADObject -WhatIf');
        else lines.push('$deleted | Select-Object Name, objectClass, whenChanged, lastKnownParent |\n    Sort-Object whenChanged -Descending |\n    Format-Table -AutoSize');
        return lines.join('\n');
      }
    }
  );

  /* ------------------------------------------------------------ computers */

  SPECS.push(
    {
      id: 'ad-computers-inactive',
      t: 'Stale computer accounts',
      p: ['Computers', 'Cleanup', 'Audit'],
      d: 'Computer objects that have not authenticated for a number of days, the machines that usually no longer exist.',
      k: 'stale computers inactive lastlogondate orphaned workstations cleanup',
      base: 'Get-ADComputer -Filter *',
      vars: [DAYS('days', 'Inactive for at least (days)', 90)],
      pre: CUT('days', 90),
      cols: ['*Name', '*OperatingSystem', '*LastLogonDate', '*Enabled', 'IPv4Address', 'whenCreated', 'Description', '*DistinguishedName'],
      filt: [['enabled', 'Enabled computers only', 'Enabled -eq $true', null, true]],
      where: [
        ['stale', 'Last logon older than the day count', '$_.LastLogonDate -lt $cut', null, true],
        ['never', 'Include computers that never authenticated', '-not $_.LastLogonDate']
      ],
      sort: [['Oldest logon first', 'LastLogonDate'], ['Name', 'Name']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-computers-os-inventory',
      t: 'Operating system inventory',
      p: ['Computers', 'Reporting', 'Audit'],
      d: 'Counts the machines per operating system, the fastest way to see what is still running in the domain.',
      k: 'operatingsystem inventory count group-object version build servers workstations',
      base: 'Get-ADComputer -Filter *',
      cols: ['*Name', '*OperatingSystem', '*OperatingSystemVersion', '*LastLogonDate', 'Enabled', 'IPv4Address', 'DistinguishedName'],
      filt: [
        ['enabled', 'Enabled computers only', 'Enabled -eq $true', null, true],
        ['servers', 'Servers only', "OperatingSystem -like '*Server*'"]
      ],
      tail: {
        label: 'Summary', items: [
          ['none', 'No summary, list the columns'],
          ['os', 'Count per operating system', 'Group-Object OperatingSystem -NoElement |\n    Sort-Object Count -Descending', true],
          ['osver', 'Count per OS and version', 'Group-Object OperatingSystem, OperatingSystemVersion -NoElement |\n    Sort-Object Count -Descending']
        ]
      },
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-computers-unsupported-os',
      t: 'Unsupported operating systems',
      p: ['Computers', 'Security', 'Audit'],
      d: 'Flags machines still running an out of support Windows version, the ones auditors ask about first.',
      k: 'end of life eol windows 7 2008 2012 xp legacy unsupported risk',
      base: 'Get-ADComputer -Filter *',
      cols: ['*Name', '*OperatingSystem', '*OperatingSystemVersion', '*LastLogonDate', '*Enabled', 'IPv4Address', '*DistinguishedName'],
      filt: [['enabled', 'Enabled computers only', 'Enabled -eq $true', null, true]],
      where: [['eol', 'Out of support Windows versions', "$_.OperatingSystem -match 'Windows (XP|Vista|7|8|Server 2003|Server 2008|Server 2012)'", null, true]],
      sort: [['Operating system', 'OperatingSystem'], ['Last logon', 'LastLogonDate']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-computers-disabled',
      t: 'Disabled computer accounts',
      p: ['Computers', 'Cleanup'],
      d: 'Lists disabled machine accounts, normally the staging area before deletion.',
      k: 'disabled computers cleanup decommission staging',
      base: 'Get-ADComputer -Filter *',
      cols: ['*Name', '*OperatingSystem', '*whenChanged', '*LastLogonDate', 'Description', '*DistinguishedName'],
      filt: [['disabled', 'Disabled only', 'Enabled -eq $false', null, true]],
      sort: [['Last changed', 'whenChanged -Descending'], ['Name', 'Name']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-computers-recently-created',
      t: 'Recently joined computers',
      p: ['Computers', 'Audit', 'Security'],
      d: 'Machines added to the domain in the last few days, including who created the object where that is recorded.',
      k: 'domain join new computers whencreated audit rogue',
      base: 'Get-ADComputer -Filter *',
      vars: [DAYS('days', 'Joined in the last (days)', 7)],
      pre: CUT('days', 7),
      cols: ['*Name', '*whenCreated', '*OperatingSystem', '*Enabled', 'IPv4Address', 'ms-DS-CreatorSID', '*DistinguishedName'],
      where: [['recent', 'Created after the cut-off date', '$_.whenCreated -ge $cut', null, true]],
      sort: [['Newest first', 'whenCreated -Descending']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-computers-per-ou-count',
      t: 'Computer count per OU',
      p: ['Computers', 'Reporting'],
      d: 'Shows how the machine accounts are spread over the OU structure.',
      k: 'group-object ou count computers distribution inventory',
      base: 'Get-ADComputer -Filter *',
      cols: [
        ['OU', "@{N='OU';E={($_.DistinguishedName -split ',',2)[1]}}", [], 'Parent OU taken from the distinguished name.', true],
        '*Name', '*OperatingSystem', 'Enabled'
      ],
      filt: [['enabled', 'Enabled computers only', 'Enabled -eq $true']],
      tail: {
        label: 'Summary', items: [
          ['none', 'No summary, list the columns'],
          ['count', 'Count per OU', "Group-Object { ($_.DistinguishedName -split ',',2)[1] } -NoElement |\n    Sort-Object Count -Descending", true]
        ]
      },
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-computers-laps',
      t: 'LAPS password status',
      p: ['Computers', 'Security', 'Audit'],
      d: 'Reports which machines have a managed local administrator password and when it expires, for legacy LAPS and Windows LAPS.',
      k: 'laps ms-mcs-admpwd mslaps local administrator password expiration coverage',
      req: 'ActiveDirectory module plus rights to read the LAPS attributes.',
      base: 'Get-ADComputer -Filter *',
      cols: [
        '*Name', '*OperatingSystem',
        ['LegacyLapsSet', "@{N='LegacyLapsSet';E={[bool]$_.'ms-Mcs-AdmPwdExpirationTime'}}", ["'ms-Mcs-AdmPwdExpirationTime'"], 'Legacy Microsoft LAPS attribute.', true],
        ['LegacyLapsExpiry', "@{N='LegacyLapsExpiry';E={if ($_.'ms-Mcs-AdmPwdExpirationTime') { [DateTime]::FromFileTime($_.'ms-Mcs-AdmPwdExpirationTime') }}}", ["'ms-Mcs-AdmPwdExpirationTime'"], null, true],
        ['WindowsLapsSet', "@{N='WindowsLapsSet';E={[bool]$_.'msLAPS-PasswordExpirationTime'}}", ["'msLAPS-PasswordExpirationTime'"], 'Windows LAPS attribute, Windows 11 and Server 2019 upward.', true],
        ['LegacyLapsPassword', "@{N='LegacyLapsPassword';E={$_.'ms-Mcs-AdmPwd'}}", ["'ms-Mcs-AdmPwd'"], 'Only readable by accounts delegated the LAPS read right.'],
        'LastLogonDate', 'DistinguishedName'
      ],
      filt: [['enabled', 'Enabled computers only', 'Enabled -eq $true', null, true]],
      where: [['missing', 'Only machines without a LAPS password', "-not $_.'ms-Mcs-AdmPwdExpirationTime' -and -not $_.'msLAPS-PasswordExpirationTime'"]],
      sort: [['Name', 'Name']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-computers-bitlocker-keys',
      t: 'BitLocker recovery keys in AD',
      p: ['Computers', 'Security', 'Audit'],
      d: 'Finds the BitLocker recovery information stored under each computer object, or the machines that have none.',
      k: 'bitlocker msfve-recoveryinformation recovery key escrow encryption compliance',
      req: 'ActiveDirectory module plus rights to read BitLocker recovery information.',
      more: [
        {
          id: 'mode', label: 'Report', type: 'single', items: [
            { id: 'keys', label: 'Machines with recovery keys', default: true },
            { id: 'missing', label: 'Machines without any key' }
          ]
        },
        { id: 'showKey', label: 'Include the recovery password', type: 'multi', items: [{ id: 'yes', label: 'Show the key itself' }] }
      ],
      build: sel => {
        const cols = ["@{N='Computer';E={$computer.Name}}", 'whenCreated', 'Name'];
        if (sel.showKey.has('yes')) cols.push("@{N='RecoveryPassword';E={$_.'msFVE-RecoveryPassword'}}");
        const lines = [
          '$report = foreach ($computer in Get-ADComputer -Filter *) {',
          '    $keys = Get-ADObject -SearchBase $computer.DistinguishedName -Filter "objectClass -eq \'msFVE-RecoveryInformation\'" -Properties whenCreated, \'msFVE-RecoveryPassword\''
        ];
        if (sel.mode === 'missing') {
          lines.push('    if (-not $keys) { $computer | Select-Object Name, DistinguishedName }');
        } else {
          lines.push('    $keys | Select-Object ' + cols.join(', '));
        }
        lines.push('}');
        lines.push('$report | Sort-Object Computer | Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      id: 'ad-computers-ping-report',
      t: 'Ping every computer in an OU',
      p: ['Computers', 'Network', 'Troubleshooting'],
      d: 'Tests whether the machine accounts in the directory answer on the network, with the resolved address.',
      k: 'test-connection ping online offline reachability sweep dns resolve',
      more: [
        { id: 'ou', label: 'OU to test', type: 'text', placeholder: 'OU=Workstations,DC=contoso,DC=com' },
        {
          id: 'show', label: 'Show', type: 'single', items: [
            { id: 'all', label: 'All machines', default: true },
            { id: 'offline', label: 'Offline only' },
            { id: 'online', label: 'Online only' }
          ]
        }
      ],
      build: sel => {
        const ou = q(sel.ou);
        const lines = [
          '$computers = Get-ADComputer -Filter \'Enabled -eq $true\'' + (ou ? " -SearchBase '" + ou + "'" : ''),
          '$report = foreach ($computer in $computers) {',
          '    $online = Test-Connection -ComputerName $computer.Name -Count 1 -Quiet -ErrorAction SilentlyContinue',
          '    [pscustomobject]@{',
          '        Name    = $computer.Name',
          '        Online  = $online',
          '        Address = (Resolve-DnsName -Name $computer.Name -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty IPAddress)',
          '    }',
          '}'
        ];
        if (sel.show === 'offline') lines.push('$report = $report | Where-Object { -not $_.Online }');
        if (sel.show === 'online') lines.push('$report = $report | Where-Object { $_.Online }');
        lines.push('$report | Sort-Object Name | Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      id: 'ad-computer-secure-channel',
      t: 'Check and repair the secure channel',
      p: ['Computers', 'Troubleshooting'],
      d: 'Verifies the trust relationship between a machine and the domain, and repairs it without a rejoin.',
      k: 'test-computersecurechannel trust relationship failed repair reset machine password',
      req: 'Run locally on the machine in an elevated PowerShell session.',
      more: [
        {
          id: 'mode', label: 'Action', type: 'single', items: [
            { id: 'test', label: 'Test only', default: true },
            { id: 'repair', label: 'Test and repair' },
            { id: 'reset', label: 'Reset the machine account password' }
          ]
        },
        { id: 'server', label: 'Domain controller (optional)', type: 'text', placeholder: 'dc01.contoso.com' }
      ],
      build: sel => {
        const srv = q(sel.server) ? " -Server '" + q(sel.server) + "'" : '';
        if (sel.mode === 'repair') {
          return [
            '$cred = Get-Credential',
            'Test-ComputerSecureChannel -Repair -Credential $cred' + srv + ' -Verbose'
          ].join('\n');
        }
        if (sel.mode === 'reset') {
          return [
            '$cred = Get-Credential',
            'Reset-ComputerMachinePassword' + srv + ' -Credential $cred',
            'Test-ComputerSecureChannel' + srv
          ].join('\n');
        }
        return 'Test-ComputerSecureChannel -Verbose' + srv;
      }
    },
    {
      id: 'ad-computers-cleanup-stale',
      t: 'Disable, move or delete stale computers',
      p: ['Computers', 'Cleanup', 'Bulk changes'],
      d: 'Full cleanup pass for machine accounts, with a dry run switch and a CSV log before anything changes.',
      k: 'remove-adcomputer disable move stale cleanup whatif bulk decommission',
      more: [
        { id: 'days', label: 'Inactive for at least (days)', type: 'number', placeholder: '180', value: '180' },
        { id: 'ou', label: 'Move to OU (optional)', type: 'text', placeholder: 'OU=Retired,DC=contoso,DC=com' },
        {
          id: 'steps', label: 'Actions', type: 'multi', items: [
            { id: 'log', label: 'Write a CSV log first', default: true },
            { id: 'disable', label: 'Disable the account', default: true },
            { id: 'describe', label: 'Stamp the description with the date', default: true },
            { id: 'delete', label: 'Delete the account (recursive)' },
            { id: 'whatIf', label: 'Dry run (-WhatIf)', default: true }
          ]
        }
      ],
      build: sel => {
        const whatIf = sel.steps.has('whatIf') ? ' -WhatIf' : '';
        const lines = [
          '$cut = (Get-Date).AddDays(-' + num(sel.days, 180) + ')',
          "$stale = Get-ADComputer -Filter 'Enabled -eq $true' -Properties LastLogonDate, OperatingSystem, Description |",
          '    Where-Object { $_.LastLogonDate -lt $cut }'
        ];
        if (sel.steps.has('log')) lines.push('$stale | Select-Object Name, OperatingSystem, LastLogonDate, DistinguishedName |\n    Export-Csv -Path .\\StaleComputers.csv -NoTypeInformation -Encoding UTF8');
        lines.push('$stale | ForEach-Object {');
        if (sel.steps.has('describe')) lines.push('    Set-ADComputer -Identity $_ -Description "Stale $(Get-Date -Format yyyy-MM-dd)"' + whatIf);
        if (sel.steps.has('disable')) lines.push('    Disable-ADAccount -Identity $_' + whatIf);
        if (q(sel.ou)) lines.push("    Move-ADObject -Identity $_ -TargetPath '" + q(sel.ou) + "'" + whatIf);
        if (sel.steps.has('delete')) lines.push('    Remove-ADObject -Identity $_ -Recursive -Confirm:$false' + whatIf);
        lines.push('}');
        return lines.join('\n');
      }
    }
  );

  /* --------------------------------------------------------------- groups */

  SPECS.push(
    {
      id: 'ad-group-members',
      t: 'Members of a group',
      p: ['Groups', 'Users', 'Audit'],
      d: 'Lists the members of one group, optionally expanding nested groups into the real user accounts.',
      k: 'get-adgroupmember recursive nested members list membership export',
      base: sel => "Get-ADGroupMember -Identity '" + (q(sel.group) || 'Domain Admins') + "'" + (sel.opts.has('recursive') ? ' -Recursive' : ''),
      props: false,
      vars: [{ id: 'group', label: 'Group name', type: 'text', ph: 'Domain Admins' }],
      more: [{
        id: 'opts', label: 'Depth', type: 'multi',
        items: [{ id: 'recursive', label: 'Expand nested groups (-Recursive)', default: true }]
      }],
      cols: ['*Name', '*SamAccountName', '*objectClass', '*distinguishedName'],
      sort: [['Name', 'Name'], ['Object class', 'objectClass']],
      c: 1
    },
    {
      id: 'ad-groups-privileged-members',
      t: 'Members of the privileged groups',
      p: ['Groups', 'Security', 'Audit'],
      d: 'Expands the built-in high privilege groups in one pass, the report every security review starts with.',
      k: 'domain admins enterprise admins schema administrators privileged tier 0 review',
      more: [
        {
          id: 'groups', label: 'Groups', type: 'multi', wide: true, items: [
            { id: 'Domain Admins', label: 'Domain Admins', default: true },
            { id: 'Enterprise Admins', label: 'Enterprise Admins', default: true },
            { id: 'Schema Admins', label: 'Schema Admins', default: true },
            { id: 'Administrators', label: 'Administrators', default: true },
            { id: 'Account Operators', label: 'Account Operators' },
            { id: 'Server Operators', label: 'Server Operators' },
            { id: 'Backup Operators', label: 'Backup Operators' },
            { id: 'Print Operators', label: 'Print Operators' },
            { id: 'DnsAdmins', label: 'DnsAdmins' },
            { id: 'Group Policy Creator Owners', label: 'Group Policy Creator Owners' }
          ]
        },
        { id: 'depth', label: 'Depth', type: 'multi', items: [{ id: 'recursive', label: 'Expand nested groups', default: true }] },
        { id: 'detail', label: 'Detail', type: 'multi', items: [{ id: 'account', label: 'Add account status and password age', default: true }] },
        {
          id: 'output', label: 'Output', type: 'single', items: [
            { id: 'table', label: 'Table (Format-Table)', default: true },
            { id: 'csv', label: 'CSV file (Export-Csv)' },
            { id: 'grid', label: 'Grid view (Out-GridView)' }
          ]
        }
      ],
      build: sel => {
        const groups = Array.from(sel.groups);
        const list = (groups.length ? groups : ['Domain Admins']).map(g => "'" + q(g) + "'").join(', ');
        const rec = sel.depth.has('recursive') ? ' -Recursive' : '';
        const lines = [
          '$groups = ' + list,
          '$report = foreach ($group in $groups) {',
          '    Get-ADGroupMember -Identity $group' + rec + ' -ErrorAction SilentlyContinue | ForEach-Object {'
        ];
        if (sel.detail.has('account')) {
          lines.push('        $account = Get-ADUser -Identity $_.distinguishedName -Properties Enabled, PasswordLastSet, LastLogonDate -ErrorAction SilentlyContinue');
          lines.push('        [pscustomobject]@{');
          lines.push('            Group           = $group');
          lines.push('            Name            = $_.Name');
          lines.push('            SamAccountName  = $_.SamAccountName');
          lines.push('            Class           = $_.objectClass');
          lines.push('            Enabled         = $account.Enabled');
          lines.push('            PasswordLastSet = $account.PasswordLastSet');
          lines.push('            LastLogonDate   = $account.LastLogonDate');
          lines.push('        }');
        } else {
          lines.push("        $_ | Select-Object @{N='Group';E={$group}}, Name, SamAccountName, objectClass");
        }
        lines.push('    }');
        lines.push('}');
        if (sel.output === 'csv') lines.push('$report | Sort-Object Group, Name | Export-Csv -Path .\\PrivilegedMembers.csv -NoTypeInformation -Encoding UTF8');
        else if (sel.output === 'grid') lines.push("$report | Sort-Object Group, Name | Out-GridView -Title 'Privileged group members'");
        else lines.push('$report | Sort-Object Group, Name | Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      id: 'ad-groups-empty',
      t: 'Empty groups',
      p: ['Groups', 'Cleanup'],
      d: 'Groups without a single member, usually left over from old projects.',
      k: 'empty groups no members unused cleanup housekeeping',
      base: 'Get-ADGroup -Filter *',
      cols: ['*Name', '*GroupCategory', '*GroupScope', '*whenCreated', 'ManagedBy', 'Description', '*DistinguishedName'],
      where: [['empty', 'No members', '-not $_.Members', null, true]],
      sort: [['Name', 'Name'], ['Oldest first', 'whenCreated']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-groups-largest',
      t: 'Largest groups by member count',
      p: ['Groups', 'Reporting', 'Audit'],
      d: 'Ranks groups by how many members they hold, which exposes the ones near the token size limit.',
      k: 'member count largest biggest token bloat kerberos size groups',
      base: 'Get-ADGroup -Filter *',
      cols: [
        '*Name',
        ['MemberCount', "@{N='MemberCount';E={$_.Members.Count}}", ['Members'], 'Direct members only, nested groups count as one.', true],
        '*GroupScope', '*GroupCategory', 'ManagedBy', 'Description', '*DistinguishedName'
      ],
      vars: [DAYS('min', 'Minimum member count', 50)],
      where: [['min', 'Above the minimum member count', sel => '$_.Members.Count -ge ' + num(sel.min, 50), null, true]],
      sort: [['Largest first', '{$_.Members.Count} -Descending']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-groups-nested',
      t: 'Groups nested inside groups',
      p: ['Groups', 'Audit', 'Troubleshooting'],
      d: 'Shows which groups contain other groups, the usual cause of surprise permissions.',
      k: 'nested nesting group in group memberof chain depth circular',
      base: 'Get-ADGroup -Filter *',
      cols: [
        '*Name',
        ['NestedGroups', "@{N='NestedGroups';E={($_.Members | Where-Object { $_ -like 'CN=*' } | ForEach-Object { (Get-ADObject $_).Name }) -join ', '}}", ['Members'], 'Member objects that are groups themselves.', true],
        '*GroupScope', '*GroupCategory', 'DistinguishedName'
      ],
      where: [['nested', 'Contains at least one group', "(Get-ADGroupMember -Identity $_ | Where-Object { $_.objectClass -eq 'group' })", null, true]],
      sort: [['Name', 'Name']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-groups-recently-created',
      t: 'Recently created groups',
      p: ['Groups', 'Audit', 'Security'],
      d: 'Groups added in the last few days, worth reviewing when permissions appear out of nowhere.',
      k: 'new groups whencreated audit recent review',
      base: 'Get-ADGroup -Filter *',
      vars: [DAYS('days', 'Created in the last (days)', 7)],
      pre: CUT('days', 7),
      cols: ['*Name', '*whenCreated', '*GroupCategory', '*GroupScope', 'ManagedBy', 'Description', '*DistinguishedName'],
      where: [['recent', 'Created after the cut-off date', '$_.whenCreated -ge $cut', null, true]],
      sort: [['Newest first', 'whenCreated -Descending']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-groups-by-scope',
      t: 'Groups by scope and type',
      p: ['Groups', 'Reporting'],
      d: 'Inventory of security versus distribution groups and their scope, with an optional summary count.',
      k: 'groupscope groupcategory global universal domainlocal security distribution inventory',
      base: 'Get-ADGroup -Filter *',
      cols: ['*Name', '*GroupCategory', '*GroupScope', '*whenCreated', 'ManagedBy', 'Description', '*DistinguishedName'],
      filt: [
        ['security', 'Security groups only', "GroupCategory -eq 'Security'"],
        ['distribution', 'Distribution groups only', "GroupCategory -eq 'Distribution'"],
        ['universal', 'Universal scope only', "GroupScope -eq 'Universal'"]
      ],
      tail: {
        label: 'Summary', items: [
          ['none', 'No summary, list the columns', null, true],
          ['count', 'Count per category and scope', 'Group-Object GroupCategory, GroupScope -NoElement |\n    Sort-Object Count -Descending']
        ]
      },
      sort: [['Name', 'Name']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-groups-managed-by',
      t: 'Group owners (managedBy)',
      p: ['Groups', 'Reporting', 'Cleanup'],
      d: 'Shows who owns each group, and which groups have no owner recorded at all.',
      k: 'managedby owner responsible attestation review unowned',
      base: 'Get-ADGroup -Filter *',
      cols: [
        '*Name',
        ['Owner', "@{N='Owner';E={if ($_.ManagedBy) { (Get-ADObject $_.ManagedBy).Name }}}", ['ManagedBy'], 'Resolves the managedBy DN to a name.', true],
        '*GroupCategory', '*GroupScope', 'Description', '*DistinguishedName'
      ],
      where: [['unowned', 'Only groups without an owner', '-not $_.ManagedBy']],
      sort: [['Name', 'Name']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-groups-compare',
      t: 'Compare the membership of two groups',
      p: ['Groups', 'Audit', 'Troubleshooting'],
      d: 'Diffs two groups so you can see who is in one and not the other, for example before merging them.',
      k: 'compare-object diff two groups membership difference merge migration',
      more: [
        { id: 'a', label: 'First group', type: 'text', placeholder: 'App-Users-Old' },
        { id: 'b', label: 'Second group', type: 'text', placeholder: 'App-Users-New' },
        {
          id: 'show', label: 'Show', type: 'single', items: [
            { id: 'diff', label: 'Differences only', default: true },
            { id: 'all', label: 'Differences and matches' },
            { id: 'onlyA', label: 'Only in the first group' },
            { id: 'onlyB', label: 'Only in the second group' }
          ]
        }
      ],
      build: sel => {
        const a = q(sel.a) || 'App-Users-Old';
        const b = q(sel.b) || 'App-Users-New';
        const lines = [
          "$a = Get-ADGroupMember -Identity '" + a + "' -Recursive | Select-Object -ExpandProperty SamAccountName",
          "$b = Get-ADGroupMember -Identity '" + b + "' -Recursive | Select-Object -ExpandProperty SamAccountName",
          '$diff = Compare-Object -ReferenceObject $a -DifferenceObject $b' + (sel.show === 'all' ? ' -IncludeEqual' : '')
        ];
        if (sel.show === 'onlyA') lines.push("$diff | Where-Object SideIndicator -eq '<=' | Select-Object -ExpandProperty InputObject");
        else if (sel.show === 'onlyB') lines.push("$diff | Where-Object SideIndicator -eq '=>' | Select-Object -ExpandProperty InputObject");
        else lines.push("$diff | Select-Object @{N='Account';E={$_.InputObject}}, @{N='OnlyIn';E={if ($_.SideIndicator -eq '<=') { '" + a + "' } elseif ($_.SideIndicator -eq '=>') { '" + b + "' } else { 'both' }}} |\n    Format-Table -AutoSize");
        return lines.join('\n');
      }
    },
    {
      id: 'ad-group-bulk-membership',
      t: 'Bulk add or remove group members',
      p: ['Groups', 'Bulk changes'],
      d: 'Adds or removes a list of accounts from a group, taking the names from a CSV or a copied text list.',
      k: 'add-adgroupmember remove-adgroupmember bulk csv membership mass whatif',
      more: [
        { id: 'group', label: 'Group name', type: 'text', placeholder: 'App-Users' },
        { id: 'source', label: 'CSV path (column SamAccountName)', type: 'text', placeholder: '.\\members.csv' },
        {
          id: 'action', label: 'Action', type: 'single', items: [
            { id: 'add', label: 'Add members', default: true },
            { id: 'remove', label: 'Remove members' }
          ]
        },
        { id: 'flags', label: 'Options', type: 'multi', items: [{ id: 'whatIf', label: 'Dry run (-WhatIf)', default: true }] }
      ],
      build: sel => {
        const group = q(sel.group) || 'App-Users';
        const path = q(sel.source) || '.\\members.csv';
        const cmd = sel.action === 'remove' ? 'Remove-ADGroupMember' : 'Add-ADGroupMember';
        const args = " -Identity '" + group + "' -Members $members -Confirm:$false" + (sel.flags.has('whatIf') ? ' -WhatIf' : '');
        return [
          "$members = Import-Csv -Path '" + path + "' | Select-Object -ExpandProperty SamAccountName",
          cmd + args,
          "Get-ADGroupMember -Identity '" + group + "' | Select-Object Name, SamAccountName | Format-Table -AutoSize"
        ].join('\n');
      }
    },
    {
      id: 'ad-group-copy-membership',
      t: 'Copy group membership between users',
      p: ['Groups', 'Users', 'Bulk changes'],
      d: 'Mirrors the groups of one account onto another, the usual request when someone changes role or replaces a colleague.',
      k: 'copy clone mirror membership template user groups onboarding',
      more: [
        { id: 'source', label: 'Copy from (user)', type: 'text', placeholder: 'jdoe' },
        { id: 'target', label: 'Copy to (user)', type: 'text', placeholder: 'asmith' },
        {
          id: 'flags', label: 'Options', type: 'multi', items: [
            { id: 'skipPrimary', label: 'Skip Domain Users and other primary groups', default: true },
            { id: 'whatIf', label: 'Dry run (-WhatIf)', default: true }
          ]
        }
      ],
      build: sel => {
        const source = q(sel.source) || 'jdoe';
        const target = q(sel.target) || 'asmith';
        const lines = ["$groups = Get-ADPrincipalGroupMembership -Identity '" + source + "'"];
        if (sel.flags.has('skipPrimary')) lines.push("$groups = $groups | Where-Object { $_.Name -ne 'Domain Users' }");
        lines.push('foreach ($group in $groups) {');
        lines.push("    Add-ADGroupMember -Identity $group -Members '" + target + "' -Confirm:$false" + (sel.flags.has('whatIf') ? ' -WhatIf' : ''));
        lines.push('}');
        return lines.join('\n');
      }
    },
    {
      id: 'ad-groups-orphaned-sids',
      t: 'Orphaned SIDs in group membership',
      p: ['Groups', 'Cleanup', 'Security'],
      d: 'Finds unresolved SIDs left in groups after an account was deleted, shown in the console as a raw S-1-5 string.',
      k: 'orphaned sid unresolved deleted account foreignsecurityprincipal cleanup',
      base: 'Get-ADGroup -Filter *',
      cols: [
        '*Name',
        ['OrphanedMembers', "@{N='OrphanedMembers';E={($_.Members | Where-Object { $_ -like 'CN=S-1-5-*' }) -join ', '}}", ['Members'], 'Members whose DN is still a raw SID.', true],
        '*GroupScope', 'DistinguishedName'
      ],
      where: [['orphan', 'Contains an unresolved SID', "($_.Members | Where-Object { $_ -like 'CN=S-1-5-*' })", null, true]],
      sort: [['Name', 'Name']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-group-membership-changes',
      t: 'Group membership change events',
      p: ['Groups', 'Security', 'Audit'],
      d: 'Reads the security log on the domain controllers for accounts added to or removed from groups.',
      k: '4728 4729 4732 4733 4756 4757 event log membership change audit who added',
      req: 'Security log auditing for account management, and rights to read the DC event logs.',
      more: [
        { id: 'days', label: 'Look back (days)', type: 'number', placeholder: '7', value: '7' },
        {
          id: 'kinds', label: 'Events', type: 'multi', items: [
            { id: '4728', label: 'Added to a global group (4728)', default: true },
            { id: '4729', label: 'Removed from a global group (4729)', default: true },
            { id: '4732', label: 'Added to a local group (4732)', default: true },
            { id: '4733', label: 'Removed from a local group (4733)', default: true },
            { id: '4756', label: 'Added to a universal group (4756)' },
            { id: '4757', label: 'Removed from a universal group (4757)' }
          ]
        },
        {
          id: 'scope', label: 'Where', type: 'single', items: [
            { id: 'pdc', label: 'PDC emulator', default: true },
            { id: 'all', label: 'Every domain controller' }
          ]
        },
        {
          id: 'output', label: 'Output', type: 'single', items: [
            { id: 'table', label: 'Table (Format-Table)', default: true },
            { id: 'csv', label: 'CSV file (Export-Csv)' },
            { id: 'grid', label: 'Grid view (Out-GridView)' }
          ]
        }
      ],
      build: sel => {
        const ids = Array.from(sel.kinds);
        const lines = [
          '$cut = (Get-Date).AddDays(-' + num(sel.days, 7) + ')',
          '$ids = ' + (ids.length ? ids.join(', ') : '4728, 4732'),
          sel.scope === 'all'
            ? '$dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName'
            : '$dcs = (Get-ADDomain).PDCEmulator',
          '$report = foreach ($dc in $dcs) {',
          "    Get-WinEvent -ComputerName $dc -FilterHashtable @{ LogName = 'Security'; Id = $ids; StartTime = $cut } -ErrorAction SilentlyContinue |",
          '        ForEach-Object {',
          '            [pscustomobject]@{',
          '                Time    = $_.TimeCreated',
          '                DC      = $dc',
          '                EventId = $_.Id',
          '                Group   = $_.Properties[2].Value',
          '                Member  = $_.Properties[0].Value',
          '                By      = $_.Properties[6].Value',
          '            }',
          '        }',
          '}'
        ];
        if (sel.output === 'csv') lines.push('$report | Sort-Object Time -Descending | Export-Csv -Path .\\GroupChanges.csv -NoTypeInformation -Encoding UTF8');
        else if (sel.output === 'grid') lines.push("$report | Sort-Object Time -Descending | Out-GridView -Title 'Group membership changes'");
        else lines.push('$report | Sort-Object Time -Descending | Format-Table -AutoSize');
        return lines.join('\n');
      }
    }
  );

  /* --------------------------------------------------- OUs and raw objects */

  SPECS.push(
    {
      id: 'ad-ou-list',
      t: 'Organisational unit inventory',
      p: ['Structure', 'Reporting'],
      d: 'Lists the OU tree with the delete protection flag and who manages each container.',
      k: 'organizational unit ou tree structure list inventory managedby',
      base: 'Get-ADOrganizationalUnit -Filter *',
      cols: [
        '*Name', '*DistinguishedName', '*ProtectedFromAccidentalDeletion', '*whenCreated',
        ['Depth', "@{N='Depth';E={($_.DistinguishedName -split ',OU=').Count - 1}}", [], 'How deep the OU sits in the tree.'],
        'ManagedBy', 'Description', 'gPLink'
      ],
      sort: [['Distinguished name', 'DistinguishedName'], ['Name', 'Name']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-ou-unprotected',
      t: 'OUs without delete protection',
      p: ['Structure', 'Security', 'Cleanup'],
      d: 'Finds containers that can be deleted by accident, and shows the command that protects them all at once.',
      k: 'protectedfromaccidentaldeletion protection delete accidental safeguard',
      base: 'Get-ADOrganizationalUnit -Filter *',
      cols: ['*Name', '*DistinguishedName', '*ProtectedFromAccidentalDeletion', 'whenCreated', 'ManagedBy'],
      where: [['unprotected', 'Not protected from accidental deletion', '-not $_.ProtectedFromAccidentalDeletion', null, true]],
      sort: [['Distinguished name', 'DistinguishedName']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-ou-protect-all',
      t: 'Protect every OU from deletion',
      p: ['Structure', 'Security', 'Bulk changes'],
      d: 'Sets the accidental deletion flag on every OU, or removes it from one branch when you need to reorganise.',
      k: 'set-adorganizationalunit protect accidental deletion bulk unprotect',
      more: [
        {
          id: 'action', label: 'Action', type: 'single', items: [
            { id: 'on', label: 'Enable protection', default: true },
            { id: 'off', label: 'Disable protection' }
          ]
        },
        { id: 'ou', label: 'Limit to OU (optional)', type: 'text', placeholder: 'OU=Sites,DC=contoso,DC=com' },
        { id: 'flags', label: 'Options', type: 'multi', items: [{ id: 'whatIf', label: 'Dry run (-WhatIf)', default: true }] }
      ],
      build: sel => {
        const ou = q(sel.ou);
        const value = sel.action === 'off' ? '$false' : '$true';
        return [
          'Get-ADOrganizationalUnit -Filter *' + (ou ? " -SearchBase '" + ou + "'" : '') + ' |',
          '    Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion ' + value + (sel.flags.has('whatIf') ? ' -WhatIf' : '')
        ].join('\n');
      }
    },
    {
      id: 'ad-ou-object-counts',
      t: 'Object count per OU',
      p: ['Structure', 'Reporting'],
      d: 'Counts users, computers and groups inside every OU, so you can see where the directory actually lives.',
      k: 'count objects per ou users computers groups distribution sizing',
      more: [
        {
          id: 'classes', label: 'Count', type: 'multi', items: [
            { id: 'user', label: 'Users', default: true },
            { id: 'computer', label: 'Computers', default: true },
            { id: 'group', label: 'Groups', default: true },
            { id: 'contact', label: 'Contacts' }
          ]
        },
        { id: 'ou', label: 'Limit to OU (optional)', type: 'text', placeholder: 'OU=Sites,DC=contoso,DC=com' },
        {
          id: 'output', label: 'Output', type: 'single', items: [
            { id: 'table', label: 'Table (Format-Table)', default: true },
            { id: 'csv', label: 'CSV file (Export-Csv)' },
            { id: 'grid', label: 'Grid view (Out-GridView)' }
          ]
        }
      ],
      build: sel => {
        const ou = q(sel.ou);
        const classes = Array.from(sel.classes);
        const lines = [
          'Get-ADOrganizationalUnit -Filter *' + (ou ? " -SearchBase '" + ou + "'" : '') + ' | ForEach-Object {',
          '    $ou = $_.DistinguishedName',
          '    [pscustomobject]@{',
          '        OU = $ou'
        ];
        const map = { user: 'Users', computer: 'Computers', group: 'Groups', contact: 'Contacts' };
        (classes.length ? classes : ['user']).forEach(c => {
          lines.push("        " + map[c] + " = @(Get-ADObject -SearchBase $ou -SearchScope OneLevel -Filter \"objectClass -eq '" + c + "'\").Count");
        });
        lines.push('    }');
        lines.push('} |');
        if (sel.output === 'csv') lines.push('    Export-Csv -Path .\\OUObjectCounts.csv -NoTypeInformation -Encoding UTF8');
        else if (sel.output === 'grid') lines.push("    Out-GridView -Title 'Object count per OU'");
        else lines.push('    Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      id: 'ad-ou-permissions',
      t: 'Delegated permissions on an OU',
      p: ['Structure', 'Security', 'Audit'],
      d: 'Reads the ACL of an OU and shows who was delegated rights, with an option to hide inherited entries.',
      k: 'get-acl delegation acl permissions rights ou inherited access control',
      more: [
        { id: 'ou', label: 'OU distinguished name', type: 'text', placeholder: 'OU=Staff,DC=contoso,DC=com' },
        {
          id: 'show', label: 'Show', type: 'multi', items: [
            { id: 'directOnly', label: 'Hide inherited permissions', default: true },
            { id: 'allowOnly', label: 'Allow entries only', default: true },
            { id: 'writeOnly', label: 'Write and full control rights only' }
          ]
        }
      ],
      build: sel => {
        const ou = q(sel.ou) || 'OU=Staff,DC=contoso,DC=com';
        const lines = ["$acl = Get-Acl -Path \"AD:\\" + ou + "\"", '$rules = $acl.Access'];
        if (sel.show.has('directOnly')) lines.push('$rules = $rules | Where-Object { -not $_.IsInherited }');
        if (sel.show.has('allowOnly')) lines.push("$rules = $rules | Where-Object { $_.AccessControlType -eq 'Allow' }");
        if (sel.show.has('writeOnly')) lines.push("$rules = $rules | Where-Object { $_.ActiveDirectoryRights -match 'Write|GenericAll|CreateChild|Delete' }");
        lines.push('$rules | Select-Object IdentityReference, ActiveDirectoryRights, AccessControlType, InheritanceType, IsInherited |\n    Sort-Object IdentityReference |\n    Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      id: 'ad-acl-dangerous-rights',
      t: 'Dangerous rights on directory objects',
      p: ['Security', 'Audit'],
      d: 'Hunts for non default GenericAll, WriteDacl and WriteOwner grants, the permissions used for privilege escalation.',
      k: 'genericall writedacl writeowner acl escalation bloodhound shadow admin permissions',
      more: [
        { id: 'ou', label: 'Search base (optional)', type: 'text', placeholder: 'OU=Staff,DC=contoso,DC=com' },
        {
          id: 'rights', label: 'Rights to report', type: 'multi', items: [
            { id: 'GenericAll', label: 'GenericAll', default: true },
            { id: 'WriteDacl', label: 'WriteDacl', default: true },
            { id: 'WriteOwner', label: 'WriteOwner', default: true },
            { id: 'ExtendedRight', label: 'ExtendedRight (includes password reset)' }
          ]
        },
        {
          id: 'filters', label: 'Filters', type: 'multi', items: [
            { id: 'direct', label: 'Non inherited entries only', default: true },
            { id: 'skipBuiltin', label: 'Skip built-in principals (SYSTEM, Domain Admins)', default: true }
          ]
        }
      ],
      build: sel => {
        const ou = q(sel.ou);
        const rights = Array.from(sel.rights);
        const pattern = (rights.length ? rights : ['GenericAll']).join('|');
        const lines = [
          '$objects = Get-ADObject -Filter *' + (ou ? " -SearchBase '" + ou + "'" : '') + ' -ResultSetSize 5000',
          '$report = foreach ($object in $objects) {',
          '    $acl = Get-Acl -Path "AD:\\$($object.DistinguishedName)" -ErrorAction SilentlyContinue',
          '    $acl.Access |',
          "        Where-Object { $_.ActiveDirectoryRights -match '" + pattern + "'" +
          (sel.filters.has('direct') ? ' -and -not $_.IsInherited' : '') +
          (sel.filters.has('skipBuiltin') ? " -and $_.IdentityReference -notmatch 'NT AUTHORITY|BUILTIN|Domain Admins|Enterprise Admins'" : '') + ' } |',
          "        Select-Object @{N='Object';E={$object.DistinguishedName}}, IdentityReference, ActiveDirectoryRights, IsInherited",
          '}',
          '$report | Sort-Object Object | Format-Table -AutoSize'
        ];
        return lines.join('\n');
      }
    },
    {
      id: 'ad-objects-recently-modified',
      t: 'Any object changed recently',
      p: ['Audit', 'Troubleshooting'],
      d: 'Looks across every object class for recent changes, the quickest answer to "what changed in AD last night".',
      k: 'whenchanged modified all objects audit change tracking incident',
      base: 'Get-ADObject -Filter *',
      vars: [DAYS('days', 'Changed in the last (days)', 1)],
      pre: CUT('days', 1),
      cols: ['*Name', '*ObjectClass', '*whenChanged', 'whenCreated', '*DistinguishedName'],
      where: [['recent', 'Changed after the cut-off date', '$_.whenChanged -ge $cut', null, true]],
      sort: [['Newest first', 'whenChanged -Descending']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-object-owner-report',
      t: 'Owner of directory objects',
      p: ['Security', 'Audit'],
      d: 'Reports the ACL owner per object, which should normally be Domain Admins rather than a user account.',
      k: 'owner acl ownership takeown security descriptor audit',
      more: [
        { id: 'ou', label: 'Search base (optional)', type: 'text', placeholder: 'OU=Staff,DC=contoso,DC=com' },
        {
          id: 'class', label: 'Object class', type: 'single', items: [
            { id: 'user', label: 'Users', default: true },
            { id: 'computer', label: 'Computers' },
            { id: 'group', label: 'Groups' }
          ]
        },
        { id: 'filters', label: 'Filters', type: 'multi', items: [{ id: 'odd', label: 'Only owners outside Domain Admins', default: true }] }
      ],
      build: sel => {
        const ou = q(sel.ou);
        const cmd = { user: 'Get-ADUser', computer: 'Get-ADComputer', group: 'Get-ADGroup' }[sel.class] || 'Get-ADUser';
        const lines = [
          '$report = ' + cmd + ' -Filter *' + (ou ? " -SearchBase '" + ou + "'" : '') + ' | ForEach-Object {',
          '    $acl = Get-Acl -Path "AD:\\$($_.DistinguishedName)" -ErrorAction SilentlyContinue',
          "    [pscustomobject]@{ Name = $_.Name; Owner = $acl.Owner; DistinguishedName = $_.DistinguishedName }",
          '}'
        ];
        if (sel.filters.has('odd')) lines.push("$report = $report | Where-Object { $_.Owner -notmatch 'Domain Admins|Enterprise Admins' }");
        lines.push('$report | Sort-Object Owner, Name | Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      id: 'ad-bulk-move-objects',
      t: 'Bulk move objects to another OU',
      p: ['Bulk changes', 'Structure'],
      d: 'Moves the accounts listed in a CSV, or everything in one OU, to a new container.',
      k: 'move-adobject bulk move ou reorganise migration targetpath whatif',
      more: [
        {
          id: 'source', label: 'Source', type: 'single', items: [
            { id: 'csv', label: 'CSV with a SamAccountName column', default: true },
            { id: 'ou', label: 'Everything in a source OU' }
          ]
        },
        { id: 'path', label: 'CSV path or source OU', type: 'text', placeholder: '.\\move.csv' },
        { id: 'target', label: 'Target OU', type: 'text', placeholder: 'OU=Staff,DC=contoso,DC=com' },
        { id: 'flags', label: 'Options', type: 'multi', items: [{ id: 'whatIf', label: 'Dry run (-WhatIf)', default: true }] }
      ],
      build: sel => {
        const target = q(sel.target) || 'OU=Staff,DC=contoso,DC=com';
        const whatIf = sel.flags.has('whatIf') ? ' -WhatIf' : '';
        if (sel.source === 'ou') {
          return [
            "Get-ADObject -Filter \"objectClass -eq 'user'\" -SearchBase '" + (q(sel.path) || 'OU=Old,DC=contoso,DC=com') + "' |",
            "    Move-ADObject -TargetPath '" + target + "'" + whatIf
          ].join('\n');
        }
        return [
          "Import-Csv -Path '" + (q(sel.path) || '.\\move.csv') + "' | ForEach-Object {",
          "    Get-ADUser -Identity $_.SamAccountName | Move-ADObject -TargetPath '" + target + "'" + whatIf,
          '}'
        ].join('\n');
      }
    }
  );

  /* --------------------------------------------------------- group policy */

  const GPO_REQ = 'GroupPolicy PowerShell module (RSAT) on a domain-joined machine.';

  SPECS.push(
    {
      id: 'gpo-list',
      t: 'All group policy objects',
      p: ['Group Policy', 'Reporting'],
      d: 'Inventory of every GPO with its status, owner and modification date.',
      k: 'get-gpo all list inventory gpostatus owner modification group policy',
      req: GPO_REQ,
      base: 'Get-GPO -All',
      props: false,
      cols: ['*DisplayName', '*GpoStatus', '*CreationTime', '*ModificationTime', '*Owner', 'Id', 'Description', 'WmiFilter'],
      sort: [['Last modified', 'ModificationTime -Descending'], ['Name', 'DisplayName']],
      c: 1
    },
    {
      id: 'gpo-unlinked',
      t: 'Unlinked group policy objects',
      p: ['Group Policy', 'Cleanup'],
      d: 'GPOs that are not linked anywhere, so they do nothing but still clutter SYSVOL.',
      k: 'unlinked orphaned gpo cleanup linksto unused policy',
      req: GPO_REQ,
      base: 'Get-GPO -All',
      props: false,
      cols: ['*DisplayName', '*GpoStatus', '*ModificationTime', '*CreationTime', 'Owner', 'Id'],
      where: [['unlinked', 'No links anywhere in the domain', '-not ([xml](Get-GPOReport -Guid $_.Id -ReportType Xml)).GPO.LinksTo', null, true]],
      sort: [['Name', 'DisplayName'], ['Oldest change first', 'ModificationTime']],
      c: 1
    },
    {
      id: 'gpo-empty',
      t: 'Group policies without settings',
      p: ['Group Policy', 'Cleanup'],
      d: 'Policies that contain no configured settings at all, safe candidates for removal after review.',
      k: 'empty gpo no settings extensiondata cleanup unused',
      req: GPO_REQ,
      base: 'Get-GPO -All',
      props: false,
      cols: ['*DisplayName', '*GpoStatus', '*ModificationTime', 'Owner', 'Id'],
      where: [['empty', 'No computer and no user settings', '$xml = [xml](Get-GPOReport -Guid $_.Id -ReportType Xml); -not $xml.GPO.Computer.ExtensionData -and -not $xml.GPO.User.ExtensionData', null, true]],
      sort: [['Name', 'DisplayName']],
      c: 1
    },
    {
      id: 'gpo-recently-modified',
      t: 'Recently changed group policies',
      p: ['Group Policy', 'Audit', 'Security'],
      d: 'Shows which policies changed in the last few days and who owns them.',
      k: 'modificationtime changed recent gpo audit who changed policy',
      req: GPO_REQ,
      base: 'Get-GPO -All',
      props: false,
      vars: [DAYS('days', 'Changed in the last (days)', 7)],
      pre: CUT('days', 7),
      cols: ['*DisplayName', '*ModificationTime', '*Owner', '*GpoStatus', 'CreationTime', 'Id'],
      where: [['recent', 'Changed after the cut-off date', '$_.ModificationTime -ge $cut', null, true]],
      sort: [['Newest first', 'ModificationTime -Descending']],
      c: 1
    },
    {
      id: 'gpo-links-per-ou',
      t: 'Group policy links per OU',
      p: ['Group Policy', 'Structure', 'Reporting'],
      d: 'Walks the OU tree and lists which policies are linked where, including enforced and disabled links.',
      k: 'gplink links inheritance enforced blocked ou get-gpinheritance order',
      req: GPO_REQ,
      more: [
        { id: 'ou', label: 'Start at OU (optional)', type: 'text', placeholder: 'OU=Sites,DC=contoso,DC=com' },
        {
          id: 'show', label: 'Show', type: 'multi', items: [
            { id: 'inherited', label: 'Include inherited links', default: true },
            { id: 'onlyLinked', label: 'Skip OUs without links', default: true }
          ]
        },
        {
          id: 'output', label: 'Output', type: 'single', items: [
            { id: 'table', label: 'Table (Format-Table)', default: true },
            { id: 'csv', label: 'CSV file (Export-Csv)' },
            { id: 'grid', label: 'Grid view (Out-GridView)' }
          ]
        }
      ],
      build: sel => {
        const ou = q(sel.ou);
        const prop = sel.show.has('inherited') ? 'InheritedGpoLinks' : 'GpoLinks';
        const lines = [
          'Get-ADOrganizationalUnit -Filter *' + (ou ? " -SearchBase '" + ou + "'" : '') + ' | ForEach-Object {',
          '    $inheritance = Get-GPInheritance -Target $_.DistinguishedName',
          '    $inheritance.' + prop + ' | ForEach-Object {',
          '        [pscustomobject]@{',
          '            OU       = $inheritance.Path',
          '            Policy   = $_.DisplayName',
          '            Enforced = $_.Enforced',
          '            Enabled  = $_.Enabled',
          '            Order    = $_.Order',
          '        }',
          '    }',
          '}'
        ];
        const pipe = sel.show.has('onlyLinked') ? ' | Where-Object { $_.Policy }' : '';
        if (sel.output === 'csv') lines.push('$report' + pipe + ' | Export-Csv -Path .\\GpoLinks.csv -NoTypeInformation -Encoding UTF8');
        else if (sel.output === 'grid') lines.push("$report" + pipe + " | Out-GridView -Title 'Group policy links'");
        else lines.push('$report' + pipe + ' | Format-Table -AutoSize');
        lines[0] = '$report = ' + lines[0];
        return lines.join('\n');
      }
    },
    {
      id: 'gpo-backup-all',
      t: 'Back up every group policy',
      p: ['Group Policy', 'Backup'],
      d: 'Exports all GPOs to a dated folder, the safety net to run before a change window.',
      k: 'backup-gpo export restore-gpo disaster recovery change window',
      req: GPO_REQ,
      more: [
        { id: 'path', label: 'Backup folder', type: 'text', placeholder: 'C:\\GPOBackup' },
        {
          id: 'flags', label: 'Options', type: 'multi', items: [
            { id: 'dated', label: 'Add a dated subfolder', default: true },
            { id: 'manifest', label: 'Write a CSV manifest', default: true }
          ]
        }
      ],
      build: sel => {
        const path = q(sel.path) || 'C:\\GPOBackup';
        const lines = [];
        if (sel.flags.has('dated')) {
          lines.push("$path = Join-Path '" + path + "' (Get-Date -Format 'yyyy-MM-dd')");
        } else {
          lines.push("$path = '" + path + "'");
        }
        lines.push('New-Item -Path $path -ItemType Directory -Force | Out-Null');
        lines.push("$backup = Backup-GPO -All -Path $path -Comment \"Backup $(Get-Date -Format 'yyyy-MM-dd')\"");
        if (sel.flags.has('manifest')) lines.push('$backup | Select-Object DisplayName, Id, BackupDirectory, CreationTime |\n    Export-Csv -Path (Join-Path $path \'manifest.csv\') -NoTypeInformation -Encoding UTF8');
        lines.push('$backup | Select-Object DisplayName, Id | Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      id: 'gpo-html-report',
      t: 'HTML report of a group policy',
      p: ['Group Policy', 'Reporting'],
      d: 'Writes the readable settings report for one policy or for all of them, the output you attach to a change record.',
      k: 'get-gporeport html xml settings documentation export report',
      req: GPO_REQ,
      more: [
        { id: 'name', label: 'Policy name (empty for all)', type: 'text', placeholder: 'Default Domain Policy' },
        { id: 'path', label: 'Output folder', type: 'text', placeholder: 'C:\\GPOReports' },
        {
          id: 'format', label: 'Format', type: 'single', items: [
            { id: 'Html', label: 'HTML', default: true },
            { id: 'Xml', label: 'XML' }
          ]
        }
      ],
      build: sel => {
        const path = q(sel.path) || 'C:\\GPOReports';
        const name = q(sel.name);
        const ext = sel.format === 'Xml' ? 'xml' : 'html';
        if (name) {
          return [
            "New-Item -Path '" + path + "' -ItemType Directory -Force | Out-Null",
            "Get-GPOReport -Name '" + name + "' -ReportType " + sel.format + " -Path '" + path + '\\' + name.replace(/[\\/:*?"<>|]/g, '_') + '.' + ext + "'"
          ].join('\n');
        }
        return [
          "New-Item -Path '" + path + "' -ItemType Directory -Force | Out-Null",
          'Get-GPO -All | ForEach-Object {',
          "    $file = Join-Path '" + path + "' ($_.DisplayName -replace '[\\\\/:*?\"<>|]', '_')",
          '    Get-GPOReport -Guid $_.Id -ReportType ' + sel.format + " -Path \"$file." + ext + '"',
          '}'
        ].join('\n');
      }
    },
    {
      id: 'gpo-permissions',
      t: 'Group policy permissions',
      p: ['Group Policy', 'Security', 'Audit'],
      d: 'Shows who can edit each policy, which is where a quiet privilege escalation often hides.',
      k: 'get-gppermission delegation edit rights gpo security filtering apply',
      req: GPO_REQ,
      more: [
        {
          id: 'level', label: 'Report', type: 'single', items: [
            { id: 'edit', label: 'Edit and full control only', default: true },
            { id: 'all', label: 'Every permission' }
          ]
        },
        { id: 'flags', label: 'Filters', type: 'multi', items: [{ id: 'skipBuiltin', label: 'Skip built-in principals', default: true }] }
      ],
      build: sel => {
        const lines = [
          '$report = Get-GPO -All | ForEach-Object {',
          '    $gpo = $_',
          '    Get-GPPermission -Guid $gpo.Id -All |',
          "        Select-Object @{N='Policy';E={$gpo.DisplayName}}, @{N='Trustee';E={$_.Trustee.Name}}, Permission, Inherited",
          '}'
        ];
        if (sel.level === 'edit') lines.push("$report = $report | Where-Object { $_.Permission -match 'Edit|GpoCustom|GpoEditDeleteModifySecurity' }");
        if (sel.flags.has('skipBuiltin')) lines.push("$report = $report | Where-Object { $_.Trustee -notmatch 'Domain Admins|Enterprise Admins|SYSTEM|ENTERPRISE DOMAIN CONTROLLERS|Authenticated Users' }");
        lines.push('$report | Sort-Object Policy, Trustee | Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      id: 'gpo-resultant-set',
      t: 'Resultant set of policy for a user',
      p: ['Group Policy', 'Troubleshooting'],
      d: 'Generates the RSoP report that explains which policies actually apply to a user on a machine.',
      k: 'rsop gpresult get-gpresultantsetofpolicy resultant applied troubleshoot why',
      req: GPO_REQ,
      more: [
        { id: 'user', label: 'User', type: 'text', placeholder: 'CONTOSO\\jdoe' },
        { id: 'computer', label: 'Computer', type: 'text', placeholder: 'PC-001' },
        {
          id: 'mode', label: 'Report', type: 'single', items: [
            { id: 'html', label: 'HTML report file', default: true },
            { id: 'console', label: 'Console summary (gpresult)' }
          ]
        }
      ],
      build: sel => {
        const user = q(sel.user) || 'CONTOSO\\jdoe';
        const computer = q(sel.computer) || 'PC-001';
        if (sel.mode === 'console') return 'gpresult /S ' + computer + ' /USER ' + user + ' /R /SCOPE COMPUTER';
        return [
          "Get-GPResultantSetOfPolicy -User '" + user + "' -Computer '" + computer + "' -ReportType Html -Path .\\RSoP.html",
          'Invoke-Item .\\RSoP.html'
        ].join('\n');
      }
    },
    {
      id: 'gpo-find-setting',
      t: 'Find which policy sets a setting',
      p: ['Group Policy', 'Troubleshooting'],
      d: 'Searches every GPO report for a keyword, the fast way to find the policy that pushes a registry key or script.',
      k: 'search gpo setting keyword which policy sets registry find text report',
      req: GPO_REQ,
      more: [
        { id: 'term', label: 'Search term', type: 'text', placeholder: 'ScreenSaverTimeOut' },
        { id: 'flags', label: 'Options', type: 'multi', items: [{ id: 'context', label: 'Show the matching line', default: true }] }
      ],
      build: sel => {
        const term = q(sel.term) || 'ScreenSaverTimeOut';
        const lines = [
          'Get-GPO -All | ForEach-Object {',
          '    $report = Get-GPOReport -Guid $_.Id -ReportType Xml',
          "    if ($report -match '" + term + "') {"
        ];
        if (sel.flags.has('context')) {
          lines.push("        [pscustomobject]@{ Policy = $_.DisplayName; Match = ($report -split \"`n\" | Select-String '" + term + "' | Select-Object -First 1) }");
        } else {
          lines.push('        [pscustomobject]@{ Policy = $_.DisplayName; Id = $_.Id }');
        }
        lines.push('    }');
        lines.push('} | Format-Table -AutoSize -Wrap');
        return lines.join('\n');
      }
    }
  );

  /* ------------------------------------------- domain, forest and topology */

  SPECS.push(
    {
      id: 'ad-domain-info',
      t: 'Domain overview',
      p: ['Domain', 'Reporting'],
      d: 'The core facts about the domain: functional level, PDC emulator, naming contexts and the built-in containers.',
      k: 'get-addomain functional level netbios pdc emulator distinguishedname domain sid',
      base: 'Get-ADDomain',
      props: false,
      defOut: 'list',
      cols: ['*Name', '*DNSRoot', '*NetBIOSName', '*DomainMode', '*DomainSID', '*PDCEmulator', '*RIDMaster', '*InfrastructureMaster',
        'DistinguishedName', 'Forest', 'ParentDomain', 'ChildDomains', 'ReplicaDirectoryServers', 'UsersContainer', 'ComputersContainer'],
      srv: 1
    },
    {
      id: 'ad-forest-info',
      t: 'Forest overview',
      p: ['Domain', 'Reporting'],
      d: 'Forest wide settings: functional level, domains, UPN suffixes, sites and the forest level FSMO holders.',
      k: 'get-adforest forest functional level upnsuffixes global catalog schema master domain naming',
      base: 'Get-ADForest',
      props: false,
      defOut: 'list',
      cols: ['*Name', '*ForestMode', '*RootDomain', '*Domains', '*GlobalCatalogs', '*SchemaMaster', '*DomainNamingMaster', '*Sites', 'UPNSuffixes', 'SPNSuffixes', 'ApplicationPartitions'],
      srv: 1
    },
    {
      id: 'ad-fsmo-roles',
      t: 'FSMO role holders',
      p: ['Domain', 'Troubleshooting'],
      d: 'Shows all five operation master roles in one view, with the option to check that each holder answers.',
      k: 'fsmo pdc rid infrastructure schema master domain naming operations roles netdom query',
      more: [
        {
          id: 'mode', label: 'Report', type: 'single', items: [
            { id: 'table', label: 'Table of the five roles', default: true },
            { id: 'raw', label: 'Raw domain and forest objects' },
            { id: 'netdom', label: 'netdom query fsmo' }
          ]
        },
        { id: 'check', label: 'Checks', type: 'multi', items: [{ id: 'ping', label: 'Test that each holder responds' }] }
      ],
      build: sel => {
        if (sel.mode === 'netdom') return 'netdom query fsmo';
        if (sel.mode === 'raw') {
          return [
            'Get-ADDomain | Format-List PDCEmulator, RIDMaster, InfrastructureMaster',
            'Get-ADForest | Format-List SchemaMaster, DomainNamingMaster'
          ].join('\n');
        }
        const lines = [
          '$domain = Get-ADDomain',
          '$forest = Get-ADForest',
          '$roles = [pscustomobject]@{',
          '    PDCEmulator          = $domain.PDCEmulator',
          '    RIDMaster            = $domain.RIDMaster',
          '    InfrastructureMaster = $domain.InfrastructureMaster',
          '    SchemaMaster         = $forest.SchemaMaster',
          '    DomainNamingMaster   = $forest.DomainNamingMaster',
          '}'
        ];
        if (sel.check.has('ping')) {
          lines.push('$roles.PSObject.Properties | ForEach-Object {');
          lines.push('    [pscustomobject]@{ Role = $_.Name; Holder = $_.Value; Online = Test-Connection -ComputerName $_.Value -Count 1 -Quiet }');
          lines.push('} | Format-Table -AutoSize');
        } else {
          lines.push('$roles | Format-List');
        }
        return lines.join('\n');
      }
    },
    {
      id: 'ad-schema-version',
      t: 'Schema and functional levels',
      p: ['Domain', 'Audit'],
      d: 'Reads the schema object version and translates it to the Windows Server release, next to the functional levels.',
      k: 'objectversion schema version forest functional level adprep upgrade readiness',
      more: [{ id: 'extra', label: 'Also show', type: 'multi', items: [{ id: 'levels', label: 'Domain and forest functional level', default: true }] }],
      build: sel => {
        const lines = [
          '$schema = (Get-ADRootDSE).schemaNamingContext',
          '$version = (Get-ADObject -Identity $schema -Properties objectVersion).objectVersion',
          '$names = @{',
          '    13 = \'Windows 2000\'; 30 = \'Windows Server 2003\'; 31 = \'Windows Server 2003 R2\'',
          '    44 = \'Windows Server 2008\'; 47 = \'Windows Server 2008 R2\'; 56 = \'Windows Server 2012\'',
          '    69 = \'Windows Server 2012 R2\'; 87 = \'Windows Server 2016\'; 88 = \'Windows Server 2019 or 2022\'',
          '    91 = \'Windows Server 2025\'',
          '}',
          '[pscustomobject]@{ SchemaVersion = $version; Release = $names[[int]$version] } | Format-List'
        ];
        if (sel.extra.has('levels')) {
          lines.push('Get-ADDomain | Format-List Name, DomainMode');
          lines.push('Get-ADForest | Format-List Name, ForestMode');
        }
        return lines.join('\n');
      }
    },
    {
      id: 'ad-trusts',
      t: 'Domain and forest trusts',
      p: ['Domain', 'Security', 'Audit'],
      d: 'Lists every trust with its direction and type, and whether SID filtering and selective authentication are in place.',
      k: 'get-adtrust trust direction transitive sid filtering selective authentication forest external',
      base: 'Get-ADTrust -Filter *',
      props: false,
      cols: ['*Name', '*Direction', '*TrustType', '*IntraForest', '*SIDFilteringQuarantined', '*SelectiveAuthentication', 'ForestTransitive', 'Source', 'Target', 'DistinguishedName'],
      sort: [['Name', 'Name']],
      srv: 1, c: 1
    },
    {
      id: 'ad-sites-and-subnets',
      t: 'Sites, subnets and site links',
      p: ['Replication', 'Network', 'Reporting'],
      d: 'Reports the replication topology: which subnets belong to which site, and how the sites are linked.',
      k: 'get-adreplicationsite subnet sitelink topology cost schedule replication interval',
      more: [
        {
          id: 'report', label: 'Report', type: 'single', items: [
            { id: 'subnets', label: 'Subnets per site', default: true },
            { id: 'sites', label: 'Sites with their DCs' },
            { id: 'links', label: 'Site links with cost and interval' },
            { id: 'orphan', label: 'Sites without a subnet' }
          ]
        },
        {
          id: 'output', label: 'Output', type: 'single', items: [
            { id: 'table', label: 'Table (Format-Table)', default: true },
            { id: 'csv', label: 'CSV file (Export-Csv)' },
            { id: 'grid', label: 'Grid view (Out-GridView)' }
          ]
        }
      ],
      build: sel => {
        let core;
        if (sel.report === 'sites') {
          core = [
            '$report = Get-ADReplicationSite -Filter * | ForEach-Object {',
            '    [pscustomobject]@{',
            '        Site = $_.Name',
            '        DCs  = (Get-ADDomainController -Filter "Site -eq \'$($_.Name)\'" | Select-Object -ExpandProperty HostName) -join \', \'',
            '    }',
            '}'
          ];
        } else if (sel.report === 'links') {
          core = [
            '$report = Get-ADReplicationSiteLink -Filter * -Properties Cost, ReplicationFrequencyInMinutes, SitesIncluded |',
            '    Select-Object Name, Cost, ReplicationFrequencyInMinutes,',
            '        @{N=\'Sites\';E={($_.SitesIncluded | ForEach-Object { ($_ -split \',\')[0] -replace \'CN=\' }) -join \', \'}}'
          ];
        } else if (sel.report === 'orphan') {
          core = [
            '$used = Get-ADReplicationSubnet -Filter * | Select-Object -ExpandProperty Site',
            '$report = Get-ADReplicationSite -Filter * |',
            '    Where-Object { $_.DistinguishedName -notin $used } |',
            '    Select-Object Name, DistinguishedName'
          ];
        } else {
          core = [
            '$report = Get-ADReplicationSubnet -Filter * -Properties Site, Location |',
            '    Select-Object Name, Location, @{N=\'Site\';E={if ($_.Site) { ($_.Site -split \',\')[0] -replace \'CN=\' }}}'
          ];
        }
        const lines = core.slice();
        if (sel.output === 'csv') lines.push('$report | Export-Csv -Path .\\ADSites.csv -NoTypeInformation -Encoding UTF8');
        else if (sel.output === 'grid') lines.push('$report | Out-GridView -Title \'AD sites\'');
        else lines.push('$report | Sort-Object Name | Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      id: 'ad-replication-status',
      t: 'Replication status per partner',
      p: ['Replication', 'Troubleshooting'],
      d: 'Shows the last successful replication per DC and partner, the first check when objects do not appear everywhere.',
      k: 'get-adreplicationpartnermetadata repadmin showrepl lastreplicationsuccess partner topology',
      base: 'Get-ADReplicationPartnerMetadata -Target (Get-ADDomainController -Filter *).HostName',
      props: false,
      cols: ['*Server', '*Partner', '*LastReplicationSuccess', '*LastReplicationAttempt', '*LastReplicationResult', 'ConsecutiveReplicationFailures', 'Partition', 'PartnerType'],
      where: [['failing', 'Only partners whose last attempt failed', '$_.LastReplicationResult -ne 0']],
      sort: [['Oldest success first', 'LastReplicationSuccess'], ['Server', 'Server']],
      c: 1
    },
    {
      id: 'ad-replication-failures',
      t: 'Replication failures',
      p: ['Replication', 'Troubleshooting'],
      d: 'Lists the actual replication errors per domain controller, with the failure count and first failure time.',
      k: 'get-adreplicationfailure error failure count repadmin showrepl replication broken',
      base: 'Get-ADReplicationFailure -Target (Get-ADDomainController -Filter *).HostName',
      props: false,
      cols: ['*Server', '*Partner', '*FailureCount', '*FirstFailureTime', '*LastError', 'FailureType'],
      sort: [['Most failures first', 'FailureCount -Descending']],
      c: 1
    },
    {
      id: 'ad-replication-force',
      t: 'Force replication',
      p: ['Replication', 'Troubleshooting'],
      d: 'Pushes changes out now instead of waiting for the schedule, for the whole domain or for a single object.',
      k: 'repadmin syncall sync-adobject force replication push urgent converge',
      more: [
        {
          id: 'mode', label: 'Scope', type: 'single', items: [
            { id: 'all', label: 'All partitions, all DCs', default: true },
            { id: 'object', label: 'One object to every DC' }
          ]
        },
        { id: 'object', label: 'Object (SamAccountName)', type: 'text', placeholder: 'jdoe' }
      ],
      build: sel => {
        if (sel.mode === 'object') {
          const target = q(sel.object) || 'jdoe';
          return [
            '$object = Get-ADObject -Filter "SamAccountName -eq \'' + target + '\'"',
            'Get-ADDomainController -Filter * | ForEach-Object {',
            '    Sync-ADObject -Object $object -Destination $_.HostName',
            '}'
          ].join('\n');
        }
        return [
          '(Get-ADDomain).PDCEmulator | ForEach-Object { repadmin /syncall $_ /AdeP }',
          'Get-ADReplicationPartnerMetadata -Target (Get-ADDomainController -Filter *).HostName |',
          '    Select-Object Server, Partner, LastReplicationSuccess, LastReplicationResult |',
          '    Format-Table -AutoSize'
        ].join('\n');
      }
    },
    {
      id: 'ad-dc-health-check',
      t: 'Domain controller health check',
      p: ['Domain', 'Troubleshooting', 'Reporting'],
      d: 'Runs the standard health pass over every DC: core services, dcdiag tests, free disk space and uptime.',
      k: 'dcdiag health services ntds netlogon kdc dns uptime disk space monitoring',
      req: 'ActiveDirectory module and remote management access to the domain controllers.',
      more: [
        {
          id: 'checks', label: 'Checks', type: 'multi', items: [
            { id: 'ping', label: 'Reachability', default: true },
            { id: 'services', label: 'Core services (NTDS, DNS, KDC, Netlogon, W32Time)', default: true },
            { id: 'dcdiag', label: 'dcdiag test summary' },
            { id: 'disk', label: 'Free disk space' },
            { id: 'uptime', label: 'Last boot time' }
          ]
        },
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
          '$report = Get-ADDomainController -Filter * | ForEach-Object {',
          '    $dc = $_.HostName',
          '    $row = [ordered]@{ Name = $_.Name; Site = $_.Site; IPv4 = $_.IPv4Address }'
        ];
        if (sel.checks.has('ping')) lines.push('    $row.Online = Test-Connection -ComputerName $dc -Count 1 -Quiet -ErrorAction SilentlyContinue');
        if (sel.checks.has('services')) {
          lines.push('    $services = Get-Service -ComputerName $dc -Name NTDS, DNS, KDC, Netlogon, W32Time -ErrorAction SilentlyContinue');
          lines.push('    $row.ServicesDown = ($services | Where-Object { $_.Status -ne \'Running\' } | Select-Object -ExpandProperty Name) -join \', \'');
        }
        if (sel.checks.has('dcdiag')) {
          lines.push('    $diag = dcdiag /s:$dc');
          lines.push('    $row.FailedTests = ($diag | Select-String \'failed test\' | ForEach-Object { ($_ -split \'failed test \')[1] }) -join \', \'');
        }
        if (sel.checks.has('disk')) {
          lines.push('    $disk = Get-CimInstance -ComputerName $dc -ClassName Win32_LogicalDisk -Filter "DeviceID=\'C:\'" -ErrorAction SilentlyContinue');
          lines.push('    $row.FreeGB = [math]::Round($disk.FreeSpace / 1GB, 1)');
        }
        if (sel.checks.has('uptime')) {
          lines.push('    $os = Get-CimInstance -ComputerName $dc -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue');
          lines.push('    $row.LastBoot = $os.LastBootUpTime');
        }
        lines.push('    [pscustomobject]$row');
        lines.push('}');
        if (sel.output === 'csv') lines.push('$report | Export-Csv -Path .\\DCHealth.csv -NoTypeInformation -Encoding UTF8');
        else if (sel.output === 'grid') lines.push('$report | Out-GridView -Title \'Domain controller health\'');
        else lines.push('$report | Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      id: 'ad-dc-time-sync',
      t: 'Time synchronisation of the DCs',
      p: ['Domain', 'Troubleshooting'],
      d: 'Compares the clock and the time source of every domain controller, since Kerberos fails once they drift apart.',
      k: 'w32tm time sync clock skew kerberos ntp source stripchart monitor',
      more: [
        {
          id: 'mode', label: 'Check', type: 'single', items: [
            { id: 'monitor', label: 'w32tm monitor across the domain', default: true },
            { id: 'source', label: 'Configured time source per DC' },
            { id: 'offset', label: 'Offset against the PDC emulator' }
          ]
        }
      ],
      build: sel => {
        if (sel.mode === 'monitor') return 'w32tm /monitor';
        if (sel.mode === 'offset') {
          return [
            '$pdc = (Get-ADDomain).PDCEmulator',
            'Get-ADDomainController -Filter * | ForEach-Object {',
            '    $result = w32tm /stripchart /computer:$pdc /dataonly /samples:1',
            '    [pscustomobject]@{ DC = $_.HostName; Offset = ($result | Select-Object -Last 1) }',
            '} | Format-Table -AutoSize'
          ].join('\n');
        }
        return [
          'Get-ADDomainController -Filter * | ForEach-Object {',
          '    [pscustomobject]@{',
          '        DC     = $_.HostName',
          '        Source = (w32tm /query /computer:$($_.HostName) /source)',
          '    }',
          '} | Format-Table -AutoSize'
        ].join('\n');
      }
    },
    {
      id: 'ad-sysvol-backlog',
      t: 'SYSVOL replication backlog',
      p: ['Replication', 'Troubleshooting', 'Group Policy'],
      d: 'Checks the DFSR backlog for SYSVOL between the domain controllers, which explains policies that do not arrive.',
      k: 'dfsr sysvol backlog get-dfsrbacklog replication policy scripts stuck journal wrap',
      req: 'DFS Replication management tools on the machine you run this from.',
      more: [
        { id: 'group', label: 'Replication group', type: 'text', placeholder: 'Domain System Volume', hint: 'Leave empty for the SYSVOL default.' },
        { id: 'flags', label: 'Options', type: 'multi', items: [{ id: 'state', label: 'Also show the DFSR state per DC' }] }
      ],
      build: sel => {
        const group = q(sel.group) || 'Domain System Volume';
        const lines = [
          '$dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName',
          '$report = foreach ($source in $dcs) {',
          '    foreach ($destination in $dcs | Where-Object { $_ -ne $source }) {',
          '        $backlog = Get-DfsrBacklog -GroupName \'' + group + '\' -FolderName \'SYSVOL Share\' -SourceComputerName $source -DestinationComputerName $destination -ErrorAction SilentlyContinue',
          '        [pscustomobject]@{ From = $source; To = $destination; Backlog = @($backlog).Count }',
          '    }',
          '}',
          '$report | Format-Table -AutoSize'
        ];
        if (sel.flags.has('state')) {
          lines.push('Get-ADDomainController -Filter * | ForEach-Object {');
          lines.push('    Get-DfsrState -ComputerName $_.HostName -ErrorAction SilentlyContinue | Select-Object -First 5');
          lines.push('}');
        }
        return lines.join('\n');
      }
    },
    {
      id: 'ad-directory-settings',
      t: 'Tombstone lifetime and directory safety settings',
      p: ['Domain', 'Security', 'Audit'],
      d: 'Reads the domain wide safety settings: tombstone lifetime, machine account quota, recycle bin and LDAP hardening.',
      k: 'tombstonelifetime machineaccountquota recycle bin dsheuristics ldap signing backup window',
      more: [
        {
          id: 'checks', label: 'Show', type: 'multi', items: [
            { id: 'tombstone', label: 'Tombstone lifetime', default: true },
            { id: 'quota', label: 'Machine account quota', default: true },
            { id: 'recycle', label: 'AD Recycle Bin state', default: true },
            { id: 'heuristics', label: 'dsHeuristics (anonymous LDAP)' },
            { id: 'ldap', label: 'LDAP signing requirement on the DCs' }
          ]
        }
      ],
      build: sel => {
        const lines = ['$config = (Get-ADRootDSE).configurationNamingContext'];
        if (sel.checks.has('tombstone')) {
          lines.push('Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$config" -Properties tombstoneLifetime |');
          lines.push('    Format-List Name, tombstoneLifetime');
        }
        if (sel.checks.has('quota')) {
          lines.push('Get-ADObject -Identity (Get-ADDomain).DistinguishedName -Properties \'ms-DS-MachineAccountQuota\' |');
          lines.push('    Format-List Name, \'ms-DS-MachineAccountQuota\'');
        }
        if (sel.checks.has('recycle')) {
          lines.push('Get-ADOptionalFeature -Filter "Name -like \'Recycle Bin Feature\'" | Format-List Name, EnabledScopes');
        }
        if (sel.checks.has('heuristics')) {
          lines.push('Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$config" -Properties dsHeuristics |');
          lines.push('    Format-List Name, dsHeuristics');
        }
        if (sel.checks.has('ldap')) {
          lines.push('Get-ADDomainController -Filter * | ForEach-Object {');
          lines.push('    $key = Invoke-Command -ComputerName $_.HostName -ScriptBlock {');
          lines.push('        Get-ItemProperty \'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\' -Name LDAPServerIntegrity -ErrorAction SilentlyContinue');
          lines.push('    }');
          lines.push('    [pscustomobject]@{ DC = $_.HostName; LDAPServerIntegrity = $key.LDAPServerIntegrity }');
          lines.push('} | Format-Table -AutoSize');
        }
        return lines.join('\n');
      }
    },
    {
      id: 'ad-dns-zones',
      t: 'DNS zones and aging',
      p: ['DNS', 'Network', 'Reporting'],
      d: 'Lists the DNS zones hosted on a domain controller with their type, replication scope and dynamic update setting.',
      k: 'get-dnsserverzone scavenging aging dynamic update integrated zone dns reverse lookup',
      req: 'DnsServer PowerShell module (RSAT) and rights on the DNS server.',
      base: sel => 'Get-DnsServerZone' + (q(sel.dnsServer) ? ' -ComputerName \'' + q(sel.dnsServer) + '\'' : ''),
      props: false,
      vars: [{ id: 'dnsServer', label: 'DNS server (optional)', type: 'text', ph: 'dc01.contoso.com' }],
      cols: ['*ZoneName', '*ZoneType', '*IsDsIntegrated', '*IsReverseLookupZone', '*DynamicUpdate', '*ReplicationScope', 'IsAutoCreated', 'IsPaused', 'IsShutdown'],
      sort: [['Zone name', 'ZoneName']],
      c: 1
    },
    {
      id: 'ad-dns-stale-records',
      t: 'Stale DNS records',
      p: ['DNS', 'Cleanup'],
      d: 'Finds A records that have not been refreshed for a long time, usually machines that no longer exist.',
      k: 'get-dnsserverresourcerecord stale scavenging timestamp old records cleanup a record',
      req: 'DnsServer PowerShell module (RSAT) and rights on the DNS server.',
      more: [
        { id: 'zone', label: 'Zone', type: 'text', placeholder: 'contoso.com' },
        { id: 'dnsServer', label: 'DNS server (optional)', type: 'text', placeholder: 'dc01.contoso.com' },
        { id: 'days', label: 'Not refreshed for (days)', type: 'number', placeholder: '60', value: '60' },
        {
          id: 'action', label: 'Action', type: 'single', items: [
            { id: 'list', label: 'List the records', default: true },
            { id: 'remove', label: 'Remove them (dry run)' }
          ]
        }
      ],
      build: sel => {
        const zone = q(sel.zone) || 'contoso.com';
        const server = q(sel.dnsServer) ? ' -ComputerName \'' + q(sel.dnsServer) + '\'' : '';
        const lines = [
          '$cut = (Get-Date).AddDays(-' + num(sel.days, 60) + ')',
          '$records = Get-DnsServerResourceRecord -ZoneName \'' + zone + '\' -RRType A' + server + ' |',
          '    Where-Object { $_.TimeStamp -and $_.TimeStamp -lt $cut }'
        ];
        if (sel.action === 'remove') {
          lines.push('$records | Remove-DnsServerResourceRecord -ZoneName \'' + zone + '\'' + server + ' -Force -WhatIf');
        } else {
          lines.push('$records | Select-Object HostName, TimeStamp, @{N=\'Address\';E={$_.RecordData.IPv4Address}} |');
          lines.push('    Sort-Object TimeStamp |');
          lines.push('    Format-Table -AutoSize');
        }
        return lines.join('\n');
      }
    }
  );

  /* ------------------------------------------------- security and auditing */

  const EVENT_DATA = [
    '    $data = ([xml]$_.ToXml()).Event.EventData.Data',
    '    $get = { param($name) ($data | Where-Object { $_.Name -eq $name }).\'#text\' }'
  ];

  SPECS.push(
    {
      id: 'ad-password-policy',
      t: 'Domain password and lockout policy',
      p: ['Security', 'Audit'],
      d: 'The default domain policy: length, history, age and the lockout thresholds that apply to everyone.',
      k: 'get-addefaultdomainpasswordpolicy complexity lockout threshold history minimum length age',
      base: 'Get-ADDefaultDomainPasswordPolicy',
      props: false,
      defOut: 'list',
      cols: ['*MinPasswordLength', '*ComplexityEnabled', '*PasswordHistoryCount', '*MaxPasswordAge', '*MinPasswordAge',
        '*LockoutThreshold', '*LockoutDuration', '*LockoutObservationWindow', 'ReversibleEncryptionEnabled', 'DistinguishedName'],
      srv: 1
    },
    {
      id: 'ad-fine-grained-policies',
      t: 'Fine grained password policies',
      p: ['Security', 'Audit'],
      d: 'Lists the PSOs, their precedence and exactly which users and groups they apply to.',
      k: 'psofine grained password policy precedence applies to adfinegrainedpasswordpolicy subject',
      more: [{ id: 'extra', label: 'Also show', type: 'multi', items: [{ id: 'subjects', label: 'The users and groups each policy applies to', default: true }] }],
      build: sel => {
        const lines = ['$policies = Get-ADFineGrainedPasswordPolicy -Filter *'];
        if (sel.extra.has('subjects')) {
          lines.push('$policies | ForEach-Object {');
          lines.push('    [pscustomobject]@{');
          lines.push('        Name         = $_.Name');
          lines.push('        Precedence   = $_.Precedence');
          lines.push('        MinLength    = $_.MinPasswordLength');
          lines.push('        MaxAge       = $_.MaxPasswordAge');
          lines.push('        Lockout      = $_.LockoutThreshold');
          lines.push('        AppliesTo    = (Get-ADFineGrainedPasswordPolicySubject -Identity $_.Name | Select-Object -ExpandProperty Name) -join \', \'');
          lines.push('    }');
          lines.push('} | Format-Table -AutoSize');
        } else {
          lines.push('$policies | Format-Table Name, Precedence, MinPasswordLength, MaxPasswordAge, LockoutThreshold -AutoSize');
        }
        return lines.join('\n');
      }
    },
    {
      id: 'ad-krbtgt-password-age',
      t: 'krbtgt password age',
      p: ['Security', 'Audit'],
      d: 'The krbtgt password signs every Kerberos ticket, so its age matters after any suspected compromise.',
      k: 'krbtgt golden ticket kerberos reset password age rodc twice compromise',
      more: [
        { id: 'extra', label: 'Include', type: 'multi', items: [{ id: 'rodc', label: 'RODC krbtgt accounts' }] },
        {
          id: 'mode', label: 'Show', type: 'single', items: [
            { id: 'report', label: 'Age report', default: true },
            { id: 'reset', label: 'Reset command (run twice, days apart)' }
          ]
        }
      ],
      build: sel => {
        if (sel.mode === 'reset') {
          return [
            '# Reset once, let it replicate for at least 10 hours, then reset a second time.',
            '$pw = ConvertTo-SecureString -AsPlainText -Force -String ([System.Web.Security.Membership]::GeneratePassword(64, 10))',
            'Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword $pw',
            'Get-ADUser krbtgt -Properties PasswordLastSet | Format-List Name, PasswordLastSet'
          ].join('\n');
        }
        const filter = sel.extra.has('rodc') ? '"SamAccountName -like \'krbtgt*\'"' : '"SamAccountName -eq \'krbtgt\'"';
        return [
          'Get-ADUser -Filter ' + filter + ' -Properties PasswordLastSet, whenCreated |',
          '    Select-Object SamAccountName, PasswordLastSet,',
          '        @{N=\'AgeDays\';E={[int]((Get-Date) - $_.PasswordLastSet).TotalDays}} |',
          '    Format-Table -AutoSize'
        ].join('\n');
      }
    },
    {
      id: 'ad-delegation-report',
      t: 'Kerberos delegation report',
      p: ['Security', 'Audit'],
      d: 'Finds unconstrained, constrained and resource based delegation, the configurations attackers look for first.',
      k: 'trustedfordelegation constrained rbcd msds-allowedtodelegateto allowedtoactonbehalfof unconstrained escalation',
      more: [
        {
          id: 'kinds', label: 'Delegation types', type: 'multi', wide: true, items: [
            { id: 'unconstrained', label: 'Unconstrained delegation', default: true },
            { id: 'constrained', label: 'Constrained delegation', default: true },
            { id: 'rbcd', label: 'Resource based constrained delegation', default: true }
          ]
        },
        {
          id: 'classes', label: 'Object types', type: 'multi', items: [
            { id: 'computers', label: 'Computers', default: true },
            { id: 'users', label: 'Users', default: true }
          ]
        },
        {
          id: 'output', label: 'Output', type: 'single', items: [
            { id: 'table', label: 'Table (Format-Table)', default: true },
            { id: 'csv', label: 'CSV file (Export-Csv)' },
            { id: 'grid', label: 'Grid view (Out-GridView)' }
          ]
        }
      ],
      build: sel => {
        const lines = ['$report = @()'];
        const classes = [];
        if (sel.classes.has('computers')) classes.push(['Get-ADComputer', 'Computer']);
        if (sel.classes.has('users')) classes.push(['Get-ADUser', 'User']);
        (classes.length ? classes : [['Get-ADComputer', 'Computer']]).forEach(([cmd, label]) => {
          if (sel.kinds.has('unconstrained')) {
            lines.push('$report += ' + cmd + ' -Filter \'TrustedForDelegation -eq $true\' -Properties TrustedForDelegation |');
            lines.push('    Select-Object Name, @{N=\'Class\';E={\'' + label + '\'}}, @{N=\'Delegation\';E={\'Unconstrained\'}}, @{N=\'Target\';E={\'any service\'}}');
          }
          if (sel.kinds.has('constrained')) {
            lines.push('$report += ' + cmd + ' -Filter \'msDS-AllowedToDelegateTo -like "*"\' -Properties \'msDS-AllowedToDelegateTo\' |');
            lines.push('    Select-Object Name, @{N=\'Class\';E={\'' + label + '\'}}, @{N=\'Delegation\';E={\'Constrained\'}}, @{N=\'Target\';E={$_.\'msDS-AllowedToDelegateTo\' -join \', \'}}');
          }
          if (sel.kinds.has('rbcd')) {
            lines.push('$report += ' + cmd + ' -Filter * -Properties \'msDS-AllowedToActOnBehalfOfOtherIdentity\' |');
            lines.push('    Where-Object { $_.\'msDS-AllowedToActOnBehalfOfOtherIdentity\' } |');
            lines.push('    Select-Object Name, @{N=\'Class\';E={\'' + label + '\'}}, @{N=\'Delegation\';E={\'Resource based\'}}, @{N=\'Target\';E={\'see security descriptor\'}}');
          }
        });
        if (sel.output === 'csv') lines.push('$report | Sort-Object Class, Name | Export-Csv -Path .\\Delegation.csv -NoTypeInformation -Encoding UTF8');
        else if (sel.output === 'grid') lines.push('$report | Sort-Object Class, Name | Out-GridView -Title \'Kerberos delegation\'');
        else lines.push('$report | Sort-Object Class, Name | Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      id: 'ad-managed-service-accounts',
      t: 'Managed service accounts (gMSA)',
      p: ['Security', 'Users', 'Reporting'],
      d: 'Lists the group managed service accounts and which hosts are allowed to retrieve their password.',
      k: 'get-adserviceaccount gmsa msa managed service account principalsallowedtoretrievemanagedpassword',
      base: 'Get-ADServiceAccount -Filter *',
      cols: ['*Name', '*Enabled', '*PasswordLastSet', '*LastLogonDate',
        ['AllowedHosts', '@{N=\'AllowedHosts\';E={($_.PrincipalsAllowedToRetrieveManagedPassword | ForEach-Object { ($_ -split \',\')[0] -replace \'CN=\' }) -join \', \'}}', ['PrincipalsAllowedToRetrieveManagedPassword'], 'Machines that may fetch the managed password.', true],
        'ServicePrincipalNames', 'DNSHostName', 'DistinguishedName'],
      sort: [['Name', 'Name'], ['Oldest password first', 'PasswordLastSet']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-protected-users',
      t: 'Protected Users and sensitive accounts',
      p: ['Security', 'Users', 'Audit'],
      d: 'Shows the members of Protected Users next to the privileged accounts that are still missing the hardening flags.',
      k: 'protected users sensitive cannot be delegated accountnotdelegated tier 0 hardening',
      more: [
        {
          id: 'checks', label: 'Report', type: 'multi', items: [
            { id: 'members', label: 'Members of Protected Users', default: true },
            { id: 'notDelegated', label: 'Privileged accounts not marked sensitive', default: true },
            { id: 'missing', label: 'Domain Admins not in Protected Users', default: true }
          ]
        }
      ],
      build: sel => {
        const lines = [];
        if (sel.checks.has('members')) {
          lines.push('Get-ADGroupMember -Identity \'Protected Users\' |');
          lines.push('    Select-Object Name, SamAccountName, objectClass |');
          lines.push('    Format-Table -AutoSize');
        }
        if (sel.checks.has('notDelegated')) {
          lines.push('Get-ADUser -Filter \'adminCount -eq 1\' -Properties AccountNotDelegated, adminCount |');
          lines.push('    Where-Object { -not $_.AccountNotDelegated } |');
          lines.push('    Select-Object Name, SamAccountName, AccountNotDelegated |');
          lines.push('    Format-Table -AutoSize');
        }
        if (sel.checks.has('missing')) {
          lines.push('$protected = Get-ADGroupMember -Identity \'Protected Users\' | Select-Object -ExpandProperty SamAccountName');
          lines.push('Get-ADGroupMember -Identity \'Domain Admins\' -Recursive |');
          lines.push('    Where-Object { $_.SamAccountName -notin $protected } |');
          lines.push('    Select-Object Name, SamAccountName |');
          lines.push('    Format-Table -AutoSize');
        }
        return lines.join('\n');
      }
    },
    {
      id: 'ad-service-account-password-age',
      t: 'Service accounts with old passwords',
      p: ['Security', 'Users', 'Audit'],
      d: 'Accounts that act as a service and still carry a password from years ago, ranked by age.',
      k: 'service account password age rotate spn stale credentials never expires risk',
      base: 'Get-ADUser -Filter *',
      vars: [DAYS('days', 'Password older than (days)', 365)],
      pre: CUT('days', 365),
      cols: ['*Name', '*SamAccountName', '*PasswordLastSet',
        ['PasswordAgeDays', '@{N=\'PasswordAgeDays\';E={if ($_.PasswordLastSet) { [int]((Get-Date) - $_.PasswordLastSet).TotalDays }}}', ['PasswordLastSet'], null, true],
        '*ServicePrincipalName', '*PasswordNeverExpires', 'Enabled', 'LastLogonDate', 'DistinguishedName'],
      filt: [
        ['enabled', 'Enabled accounts only', 'Enabled -eq $true', null, true],
        ['spn', 'Accounts with an SPN only', 'ServicePrincipalName -like \'*\'', null, true]
      ],
      where: [['old', 'Password older than the day count', '$_.PasswordLastSet -lt $cut', null, true]],
      sort: [['Oldest password first', 'PasswordLastSet']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-users-logon-restrictions',
      t: 'Logon hour and workstation restrictions',
      p: ['Security', 'Users', 'Audit'],
      d: 'Reports which accounts are limited to certain machines or hours, and which privileged accounts have no limit at all.',
      k: 'logonworkstations logonhours restrictions allowed workstations tier admin limits',
      base: 'Get-ADUser -Filter *',
      cols: ['*Name', '*SamAccountName', '*LogonWorkstations', '*Enabled',
        ['HasLogonHours', '@{N=\'HasLogonHours\';E={[bool]$_.logonHours}}', ['logonHours'], 'True when logon hours are restricted.', true],
        'adminCount', 'LastLogonDate', 'DistinguishedName'],
      filt: [
        ['enabled', 'Enabled accounts only', 'Enabled -eq $true', null, true],
        ['admins', 'Privileged accounts only', 'adminCount -eq 1']
      ],
      where: [['restricted', 'Only accounts with a restriction', '$_.LogonWorkstations -or $_.logonHours']],
      sort: [['Name', 'Name']],
      sb: 1, srv: 1, c: 1
    },
    {
      id: 'ad-events-lockout-source',
      t: 'Where a lockout came from (4740)',
      p: ['Security', 'Troubleshooting', 'Users'],
      d: 'Reads event 4740 on the PDC emulator to show which machine locked an account out.',
      k: '4740 lockout source caller computer name pdc emulator helpdesk repeated lock',
      req: 'Rights to read the security log on the domain controllers.',
      more: [
        { id: 'user', label: 'User (empty for all)', type: 'text', placeholder: 'jdoe' },
        { id: 'days', label: 'Look back (days)', type: 'number', placeholder: '3', value: '3' },
        {
          id: 'scope', label: 'Where', type: 'single', items: [
            { id: 'pdc', label: 'PDC emulator', default: true },
            { id: 'all', label: 'Every domain controller' }
          ]
        }
      ],
      build: sel => {
        const user = q(sel.user);
        const lines = [
          '$cut = (Get-Date).AddDays(-' + num(sel.days, 3) + ')',
          sel.scope === 'all'
            ? '$dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName'
            : '$dcs = (Get-ADDomain).PDCEmulator',
          '$report = foreach ($dc in $dcs) {',
          '    Get-WinEvent -ComputerName $dc -FilterHashtable @{ LogName = \'Security\'; Id = 4740; StartTime = $cut } -ErrorAction SilentlyContinue | ForEach-Object {'
        ].concat(EVENT_DATA).concat([
          '        [pscustomobject]@{',
          '            Time     = $_.TimeCreated',
          '            DC       = $dc',
          '            Account  = & $get \'TargetUserName\'',
          '            Source   = & $get \'TargetDomainName\'',
          '        }',
          '    }',
          '}'
        ]);
        if (user) lines.push('$report = $report | Where-Object { $_.Account -eq \'' + user + '\' }');
        lines.push('$report | Sort-Object Time -Descending | Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      id: 'ad-events-failed-logons',
      t: 'Failed logons (4625)',
      p: ['Security', 'Audit', 'Troubleshooting'],
      d: 'Summarises failed sign-in attempts per account and source address, the first look at a password spray.',
      k: '4625 failed logon brute force spray audit source ip workstation failure reason',
      req: 'Rights to read the security log on the domain controllers.',
      more: [
        { id: 'days', label: 'Look back (days)', type: 'number', placeholder: '1', value: '1' },
        { id: 'user', label: 'Account (optional)', type: 'text', placeholder: 'jdoe' },
        {
          id: 'view', label: 'View', type: 'single', items: [
            { id: 'detail', label: 'Every event', default: true },
            { id: 'perUser', label: 'Count per account' },
            { id: 'perSource', label: 'Count per source address' }
          ]
        },
        {
          id: 'scope', label: 'Where', type: 'single', items: [
            { id: 'pdc', label: 'PDC emulator', default: true },
            { id: 'all', label: 'Every domain controller' }
          ]
        }
      ],
      build: sel => {
        const user = q(sel.user);
        const lines = [
          '$cut = (Get-Date).AddDays(-' + num(sel.days, 1) + ')',
          sel.scope === 'all'
            ? '$dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName'
            : '$dcs = (Get-ADDomain).PDCEmulator',
          '$report = foreach ($dc in $dcs) {',
          '    Get-WinEvent -ComputerName $dc -FilterHashtable @{ LogName = \'Security\'; Id = 4625; StartTime = $cut } -ErrorAction SilentlyContinue | ForEach-Object {'
        ].concat(EVENT_DATA).concat([
          '        [pscustomobject]@{',
          '            Time        = $_.TimeCreated',
          '            DC          = $dc',
          '            Account     = & $get \'TargetUserName\'',
          '            Workstation = & $get \'WorkstationName\'',
          '            Address     = & $get \'IpAddress\'',
          '            Status      = & $get \'Status\'',
          '        }',
          '    }',
          '}'
        ]);
        if (user) lines.push('$report = $report | Where-Object { $_.Account -eq \'' + user + '\' }');
        if (sel.view === 'perUser') lines.push('$report | Group-Object Account -NoElement | Sort-Object Count -Descending | Format-Table -AutoSize');
        else if (sel.view === 'perSource') lines.push('$report | Group-Object Address -NoElement | Sort-Object Count -Descending | Format-Table -AutoSize');
        else lines.push('$report | Sort-Object Time -Descending | Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      id: 'ad-events-account-management',
      t: 'Account creation and deletion events',
      p: ['Security', 'Audit', 'Users'],
      d: 'Tracks who created, deleted, enabled, disabled or reset accounts, straight from the DC security log.',
      k: '4720 4722 4725 4726 4738 4724 account created deleted enabled disabled password reset who',
      req: 'Rights to read the security log on the domain controllers.',
      more: [
        { id: 'days', label: 'Look back (days)', type: 'number', placeholder: '7', value: '7' },
        {
          id: 'kinds', label: 'Events', type: 'multi', wide: true, items: [
            { id: '4720', label: 'Account created (4720)', default: true },
            { id: '4726', label: 'Account deleted (4726)', default: true },
            { id: '4722', label: 'Account enabled (4722)', default: true },
            { id: '4725', label: 'Account disabled (4725)', default: true },
            { id: '4724', label: 'Password reset by an admin (4724)' },
            { id: '4738', label: 'Account changed (4738)' }
          ]
        },
        {
          id: 'scope', label: 'Where', type: 'single', items: [
            { id: 'pdc', label: 'PDC emulator', default: true },
            { id: 'all', label: 'Every domain controller' }
          ]
        }
      ],
      build: sel => {
        const ids = Array.from(sel.kinds);
        return [
          '$cut = (Get-Date).AddDays(-' + num(sel.days, 7) + ')',
          '$ids = ' + (ids.length ? ids.join(', ') : '4720, 4726'),
          sel.scope === 'all'
            ? '$dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName'
            : '$dcs = (Get-ADDomain).PDCEmulator',
          '$report = foreach ($dc in $dcs) {',
          '    Get-WinEvent -ComputerName $dc -FilterHashtable @{ LogName = \'Security\'; Id = $ids; StartTime = $cut } -ErrorAction SilentlyContinue | ForEach-Object {'
        ].concat(EVENT_DATA).concat([
          '        [pscustomobject]@{',
          '            Time    = $_.TimeCreated',
          '            EventId = $_.Id',
          '            Target  = & $get \'TargetUserName\'',
          '            By      = & $get \'SubjectUserName\'',
          '            DC      = $dc',
          '        }',
          '    }',
          '}',
          '$report | Sort-Object Time -Descending | Format-Table -AutoSize'
        ]).join('\n');
      }
    },
    {
      id: 'ad-audit-policy',
      t: 'Audit policy on the domain controllers',
      p: ['Security', 'Audit'],
      d: 'Checks which advanced audit subcategories are actually enabled, because the event reports above depend on them.',
      k: 'auditpol advanced audit policy subcategory logon account management success failure',
      req: 'Remote management access to the domain controllers.',
      more: [
        {
          id: 'scope', label: 'Where', type: 'single', items: [
            { id: 'local', label: 'This machine', default: true },
            { id: 'all', label: 'Every domain controller' }
          ]
        },
        {
          id: 'category', label: 'Category', type: 'single', items: [
            { id: 'all', label: 'All categories', default: true },
            { id: 'Account Management', label: 'Account management' },
            { id: 'Logon/Logoff', label: 'Logon and logoff' },
            { id: 'DS Access', label: 'Directory service access' }
          ]
        }
      ],
      build: sel => {
        const cat = sel.category === 'all' ? '*' : sel.category;
        const cmd = 'auditpol /get /category:"' + cat + '"';
        if (sel.scope === 'all') {
          return [
            'Get-ADDomainController -Filter * | ForEach-Object {',
            '    Write-Host $_.HostName -ForegroundColor Cyan',
            '    Invoke-Command -ComputerName $_.HostName -ScriptBlock { ' + cmd + ' }',
            '}'
          ].join('\n');
        }
        return cmd;
      }
    },
    {
      id: 'ad-ldap-query',
      t: 'Run a raw LDAP query',
      p: ['Troubleshooting', 'Reporting'],
      d: 'Runs any LDAP filter against the directory, for the searches the specific cmdlets cannot express.',
      k: 'ldapfilter get-adobject raw query oid 1.2.840.113556.1.4.1941 useraccountcontrol bitwise search',
      more: [
        { id: 'ldap', label: 'LDAP filter', type: 'text', placeholder: '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))' },
        { id: 'ou', label: 'Search base (optional)', type: 'text', placeholder: 'OU=Staff,DC=contoso,DC=com' },
        { id: 'props', label: 'Properties (comma separated)', type: 'text', placeholder: 'Name, whenCreated, userAccountControl' },
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
        const ldap = q(sel.ldap) || '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))';
        const props = sel.props.trim();
        let cmd = 'Get-ADObject -LDAPFilter \'' + ldap + '\'';
        if (q(sel.ou)) cmd += ' -SearchBase \'' + q(sel.ou) + '\'';
        if (props) cmd += ' -Properties ' + props;
        const lines = [cmd + ' |'];
        lines.push('    Select-Object ' + (props ? 'Name, ' + props : 'Name, ObjectClass, DistinguishedName') + ' |');
        if (sel.output === 'csv') lines.push('    Export-Csv -Path .\\LdapQuery.csv -NoTypeInformation -Encoding UTF8');
        else if (sel.output === 'grid') lines.push('    Out-GridView -Title \'LDAP query\'');
        else if (sel.output === 'list') lines.push('    Format-List');
        else lines.push('    Format-Table -AutoSize');
        return lines.join('\n');
      }
    },
    {
      id: 'ad-system-state-backup',
      t: 'Back up Active Directory',
      p: ['Backup', 'Domain'],
      d: 'System state backup of a domain controller, and the IFM media used to build a new DC without replicating over the network.',
      k: 'wbadmin system state backup ntdsutil ifm restore disaster recovery authoritative',
      req: 'Run in an elevated session on the domain controller, with Windows Server Backup installed.',
      more: [
        {
          id: 'mode', label: 'Task', type: 'single', items: [
            { id: 'backup', label: 'System state backup', default: true },
            { id: 'ifm', label: 'Create IFM media (ntdsutil)' },
            { id: 'status', label: 'Show the last backup result' }
          ]
        },
        { id: 'target', label: 'Target path', type: 'text', placeholder: 'E:\\Backup' }
      ],
      build: sel => {
        const target = q(sel.target) || 'E:\\Backup';
        if (sel.mode === 'ifm') {
          return [
            'ntdsutil "activate instance ntds" ifm "create sysvol full ' + target + '\\IFM" quit quit'
          ].join('\n');
        }
        if (sel.mode === 'status') {
          return [
            'Get-WBSummary | Format-List LastBackupTime, LastSuccessfulBackupTime, LastBackupResultHR',
            'Get-WinEvent -LogName \'Microsoft-Windows-Backup\' -MaxEvents 10 |',
            '    Select-Object TimeCreated, Id, LevelDisplayName, Message |',
            '    Format-Table -AutoSize -Wrap'
          ].join('\n');
        }
        return 'wbadmin start systemstatebackup -backupTarget:' + target + ' -quiet';
      }
    }
  );

  /* --- more specs are appended above this marker --- */

  SPECS.forEach(s => SCRIPTS.push(adSpec(s)));
})();

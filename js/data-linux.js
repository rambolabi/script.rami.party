'use strict';

/* ============================================================================
   Linux troubleshooting library for RHEL and Debian based machines.

   Conventions:
     Every script is plain bash with the tunables assigned at the top.
     Cleanup builders use a RUN() wrapper: in dry run mode it prints the
     command it would execute, live mode executes it.
     Where the families differ (dnf against apt, log locations) a
     distribution radio offers auto-detect through /etc/os-release.
   ========================================================================== */

(function () {
  const sq = v => String(v == null ? '' : v).trim().replace(/'/g, '');
  const num = (v, d) => (parseInt(v, 10) > 0 ? parseInt(v, 10) : d);
  const ROOT = 'Run with root privileges (sudo) on the affected machine.';

  const DISTRO = {
    id: 'distro', label: 'Distribution', type: 'single', items: [
      { id: 'auto', label: 'Auto-detect (os-release)', default: true },
      { id: 'rhel', label: 'RHEL family (dnf)' },
      { id: 'debian', label: 'Debian family (apt)' }
    ]
  };

  const DRY = {
    id: 'mode', label: 'Mode', type: 'single', items: [
      { id: 'dry', label: 'Dry run, print the commands', default: true },
      { id: 'live', label: 'Execute the cleanup' }
    ]
  };

  const runFn = dry => (dry
    ? 'RUN() { echo "WOULD RUN: $*"; }'
    : 'RUN() { "$@"; }');

  const ENTRIES = [];
  const add = e => ENTRIES.push(Object.assign({ language: 'Bash' }, e));

  /* --------------------------------------------------- why is the disk full */

  add({
    id: 'linux-disk-full-drilldown',
    title: 'Why is the disk full',
    purposes: ['Linux', 'Files & Disk', 'Troubleshooting'],
    description: 'The disk-full starting point: filesystem overview, then the biggest directories and the biggest files on the same filesystem.',
    requires: ROOT,
    keywords: 'linux disk full df du biggest directories largest files max-depth xdev drilldown space usage where did it go',
    options: [
      { id: 'path', label: 'Start at', type: 'text', placeholder: '/', value: '/' },
      { id: 'depth', label: 'Directory depth', type: 'number', placeholder: '2', value: '2' },
      { id: 'top', label: 'Show top', type: 'number', placeholder: '20', value: '20' },
      { id: 'minSize', label: 'Minimum file size', type: 'text', placeholder: '100M', value: '100M' },
      {
        id: 'parts', label: 'Sections', type: 'multi', items: [
          { id: 'overview', label: 'Filesystem overview', default: true },
          { id: 'dirs', label: 'Biggest directories', default: true },
          { id: 'files', label: 'Biggest files', default: true }
        ]
      }
    ],
    build: sel => {
      const path = sq(sel.path) || '/';
      const lines = [
        '#!/usr/bin/env bash',
        '# Filesystem overview, then drill into the biggest directories and files.',
        "TARGET='" + path + "'",
        'DEPTH=' + num(sel.depth, 2),
        'TOP=' + num(sel.top, 20),
        "MINSIZE='" + (sq(sel.minSize) || '100M') + "'"
      ];
      if (sel.parts.has('overview')) {
        lines.push('', 'echo "== Filesystem usage =="', 'df -hT "$TARGET"');
      }
      if (sel.parts.has('dirs')) {
        lines.push('', 'echo "== Biggest directories under $TARGET (same filesystem, depth $DEPTH) =="',
          'du -xh --max-depth="$DEPTH" "$TARGET" 2>/dev/null | sort -rh | head -n "$TOP"');
      }
      if (sel.parts.has('files')) {
        lines.push('', 'echo "== Files larger than $MINSIZE under $TARGET =="',
          'find "$TARGET" -xdev -type f -size +"$MINSIZE" -exec du -xh {} + 2>/dev/null | sort -rh | head -n "$TOP"');
      }
      return lines.join('\n');
    }
  });

  add({
    id: 'linux-deleted-open-files',
    title: 'Deleted files still holding space',
    purposes: ['Linux', 'Files & Disk', 'Troubleshooting'],
    description: 'When df says full but du cannot find it: files deleted while a process keeps them open, with the safe way to release the space.',
    requires: ROOT + ' lsof gives the best output, the /proc fallback works without it.',
    keywords: 'linux df du mismatch deleted open file lsof +L1 proc fd truncate release space without reboot held handle',
    options: [
      { id: 'top', label: 'Show top', type: 'number', placeholder: '20', value: '20' },
      {
        id: 'parts', label: 'Sections', type: 'multi', items: [
          { id: 'total', label: 'Total space held by deleted files', default: true },
          { id: 'howto', label: 'How to release the space', default: true }
        ]
      }
    ],
    build: sel => {
      const lines = [
        '#!/usr/bin/env bash',
        '# Space that df counts but du cannot see: deleted files a process still holds open.',
        'TOP=' + num(sel.top, 20),
        '',
        'if command -v lsof >/dev/null 2>&1; then',
        '    echo "== Deleted but open files, largest first (size in bytes) =="',
        "    lsof +L1 -nP 2>/dev/null | awk '$NF ~ /deleted/' | sort -k7,7nr | head -n \"$TOP\""
      ];
      if (sel.parts.has('total')) {
        lines.push('    echo',
          '    echo "== Total held by deleted files =="',
          "    lsof +L1 -nP 2>/dev/null | awk '$NF ~ /deleted/ { sum += $7 } END { printf \"%.1f MiB\\n\", sum/1048576 }'");
      }
      lines.push(
        'else',
        '    echo "== lsof not installed, listing through /proc =="',
        "    find /proc/[0-9]*/fd -type l -printf '%p -> %l\\n' 2>/dev/null | grep ' (deleted)' | head -n \"$TOP\"",
        'fi'
      );
      if (sel.parts.has('howto')) {
        lines.push('',
          'echo',
          'echo "== To release the space without a reboot =="',
          'echo "Truncate the file through the owning process, using the PID and FD columns above:"',
          "echo '  : > /proc/<PID>/fd/<FD>    (strip letters like w or u from the FD)'",
          'echo "Or restart the service that owns the file:"',
          "echo '  systemctl restart <service>'");
      }
      return lines.join('\n');
    }
  });

  add({
    id: 'linux-inode-exhaustion',
    title: 'Out of inodes',
    purposes: ['Linux', 'Files & Disk', 'Troubleshooting'],
    description: 'No space left on device while df shows free space usually means inodes. Shows the inode usage and the directories with the most files.',
    requires: ROOT,
    keywords: 'linux inodes df -i no space left on device millions small files sessions cache directories most entries',
    options: [
      { id: 'path', label: 'Start at', type: 'text', placeholder: '/', value: '/' },
      { id: 'top', label: 'Show top', type: 'number', placeholder: '20', value: '20' }
    ],
    build: sel => [
      '#!/usr/bin/env bash',
      '# df says space is free but writes fail: check the inodes, then find the file farms.',
      "TARGET='" + (sq(sel.path) || '/') + "'",
      'TOP=' + num(sel.top, 20),
      '',
      'echo "== Inode usage =="',
      'df -i "$TARGET"',
      '',
      'echo "== Directories with the most files under $TARGET (same filesystem) =="',
      "find \"$TARGET\" -xdev -printf '%h\\n' 2>/dev/null | sort | uniq -c | sort -rn | head -n \"$TOP\""
    ].join('\n')
  });

  add({
    id: 'linux-growing-files',
    title: 'What is growing right now',
    purposes: ['Linux', 'Files & Disk', 'Troubleshooting'],
    description: 'Catches the disk filler in the act: recently modified large files plus the processes that wrote the most since boot.',
    requires: ROOT + ' The per-process write counters come from /proc/<pid>/io.',
    keywords: 'linux growing file live fill write_bytes proc io recently modified mmin watch top writers runaway log',
    options: [
      { id: 'path', label: 'Start at', type: 'text', placeholder: '/', value: '/' },
      { id: 'minutes', label: 'Modified in the last (minutes)', type: 'number', placeholder: '10', value: '10' },
      { id: 'minSize', label: 'Minimum file size', type: 'text', placeholder: '10M', value: '10M' },
      { id: 'top', label: 'Show top', type: 'number', placeholder: '15', value: '15' },
      {
        id: 'parts', label: 'Sections', type: 'multi', items: [
          { id: 'recent', label: 'Recently modified large files', default: true },
          { id: 'writers', label: 'Processes that wrote the most', default: true },
          { id: 'watch', label: 'Watch command for a live view' }
        ]
      }
    ],
    build: sel => {
      const lines = [
        '#!/usr/bin/env bash',
        '# Find what is filling the disk while it is happening.',
        "TARGET='" + (sq(sel.path) || '/') + "'",
        'MINUTES=' + num(sel.minutes, 10),
        "MINSIZE='" + (sq(sel.minSize) || '10M') + "'",
        'TOP=' + num(sel.top, 15)
      ];
      if (sel.parts.has('recent')) {
        lines.push('',
          'echo "== Files over $MINSIZE modified in the last $MINUTES minutes =="',
          'find "$TARGET" -xdev -type f -mmin -"$MINUTES" -size +"$MINSIZE" -exec du -xh {} + 2>/dev/null | sort -rh | head -n "$TOP"');
      }
      if (sel.parts.has('writers')) {
        lines.push('',
          'echo "== Processes that wrote the most since they started =="',
          'for p in /proc/[0-9]*; do',
          "    wb=$(awk '/^write_bytes/ { print $2 }' \"$p/io\" 2>/dev/null)",
          '    [ -n "$wb" ] && [ "$wb" -gt 0 ] && printf \'%s %s %s\\n\' "$wb" "${p##*/}" "$(cat "$p/comm" 2>/dev/null)"',
          "done | sort -rn | head -n \"$TOP\" | awk '{ printf \"%10.1f MiB  pid %-7s %s\\n\", $1/1048576, $2, $3 }'");
      }
      if (sel.parts.has('watch')) {
        lines.push('',
          'echo "== Live view, interrupt with Ctrl+C =="',
          'watch -d -n 5 "df -h \'$TARGET\' | tail -n 1; du -sh \'$TARGET\' 2>/dev/null"');
      }
      return lines.join('\n');
    }
  });

  add({
    id: 'linux-log-cleanup',
    title: 'Journal and log cleanup',
    purposes: ['Linux', 'Files & Disk', 'Cleanup'],
    description: 'Measures the systemd journal and /var/log, then reclaims space from the journal and old rotated logs, dry run first.',
    requires: ROOT,
    keywords: 'linux var log journal journalctl disk-usage vacuum rotated gz old logs cleanup logrotate reclaim space',
    options: [
      { id: 'keep', label: 'Keep journal size', type: 'text', placeholder: '500M', value: '500M' },
      { id: 'age', label: 'Delete rotated logs older than (days)', type: 'number', placeholder: '30', value: '30' },
      {
        id: 'parts', label: 'Actions', type: 'multi', items: [
          { id: 'vacuum', label: 'Vacuum the journal', default: true },
          { id: 'rotated', label: 'Delete old rotated logs', default: true }
        ]
      },
      DRY
    ],
    build: sel => {
      const dry = sel.mode !== 'live';
      const lines = [
        '#!/usr/bin/env bash',
        '# Measure the log usage first, then reclaim.' + (dry ? ' Dry run: cleanup is printed, not executed.' : ''),
        runFn(dry),
        "KEEP='" + (sq(sel.keep) || '500M') + "'",
        'AGE=' + num(sel.age, 30),
        '',
        'echo "== Journal size =="',
        'journalctl --disk-usage 2>/dev/null',
        '',
        'echo "== Biggest items in /var/log =="',
        'du -xh /var/log 2>/dev/null | sort -rh | head -n 15',
        '',
        'echo "== Rotated logs older than $AGE days =="',
        "find /var/log -xdev -type f \\( -name '*.gz' -o -name '*.xz' -o -name '*.[0-9]' -o -name '*.old' \\) -mtime +\"$AGE\" -exec du -h {} + 2>/dev/null | sort -rh | head -n 15"
      ];
      if (sel.parts.has('vacuum')) {
        lines.push('', 'RUN journalctl --vacuum-size="$KEEP"');
      }
      if (sel.parts.has('rotated')) {
        lines.push('',
          dry
            ? '# Live mode replaces -print with -delete on this find:'
            : '# Deleting the rotated logs listed above:',
          "find /var/log -xdev -type f \\( -name '*.gz' -o -name '*.xz' -o -name '*.[0-9]' -o -name '*.old' \\) -mtime +\"$AGE\" " + (dry ? '-print' : '-delete'));
      }
      return lines.join('\n');
    }
  });

  add({
    id: 'linux-package-cleanup',
    title: 'Package cache and old kernels',
    purposes: ['Linux', 'Files & Disk', 'Cleanup'],
    description: 'Reclaims package manager space on either family: cache cleanup, orphaned dependencies and old kernels.',
    requires: ROOT,
    keywords: 'linux dnf clean all apt-get clean autoremove purge old kernels cache var cache rhel debian ubuntu reclaim',
    options: [
      DISTRO,
      {
        id: 'parts', label: 'Actions', type: 'multi', items: [
          { id: 'cache', label: 'Clean the package cache', default: true },
          { id: 'orphans', label: 'Remove orphaned dependencies', default: true },
          { id: 'kernels', label: 'Remove old kernels (RHEL keeps the running one)' }
        ]
      },
      DRY
    ],
    build: sel => {
      const dry = sel.mode !== 'live';
      const rhel = [];
      const debian = [];
      rhel.push('du -sh /var/cache/dnf /var/cache/yum 2>/dev/null');
      debian.push('du -sh /var/cache/apt 2>/dev/null');
      if (sel.parts.has('cache')) {
        rhel.push('RUN dnf clean all');
        debian.push('RUN apt-get clean');
      }
      if (sel.parts.has('orphans')) {
        rhel.push('RUN dnf -y autoremove');
        debian.push('RUN apt-get -y autoremove --purge');
      }
      if (sel.parts.has('kernels')) {
        rhel.push('# Removes installonly packages except the running kernel.', 'RUN dnf -y remove --oldinstallonly');
        debian.push('# apt autoremove already covers old kernels on Debian and Ubuntu.');
      }
      const indent = a => a.map(l => '        ' + l);
      const lines = [
        '#!/usr/bin/env bash',
        '# Reclaim package manager space.' + (dry ? ' Dry run: cleanup is printed, not executed.' : ''),
        runFn(dry),
        ''
      ];
      if (sel.distro === 'rhel') return lines.concat(rhel).join('\n');
      if (sel.distro === 'debian') return lines.concat(debian).join('\n');
      return lines.concat([
        '. /etc/os-release 2>/dev/null',
        'case "$ID ${ID_LIKE:-}" in',
        '    *rhel*|*fedora*|*centos*)'
      ]).concat(indent(rhel)).concat([
        '        ;;',
        '    *debian*|*ubuntu*)'
      ]).concat(indent(debian)).concat([
        '        ;;',
        '    *)',
        '        echo "Could not detect the distribution family: $ID"',
        '        ;;',
        'esac'
      ]).join('\n');
    }
  });

  add({
    id: 'linux-container-disk',
    title: 'Container storage usage',
    purposes: ['Linux', 'Files & Disk', 'Cleanup'],
    description: 'Shows what Docker or Podman is holding on disk, then prunes unused images, containers and optionally volumes.',
    requires: ROOT + ' Volume prune deletes data, keep it off unless you are certain.',
    keywords: 'linux docker podman system df prune images containers volumes overlay2 var lib docker disk usage',
    options: [
      {
        id: 'parts', label: 'Actions', type: 'multi', items: [
          { id: 'usage', label: 'Show usage breakdown', default: true },
          { id: 'prune', label: 'Prune unused images and stopped containers', default: true },
          { id: 'volumes', label: 'Prune unused volumes (deletes data)' }
        ]
      },
      DRY
    ],
    build: sel => {
      const dry = sel.mode !== 'live';
      const lines = [
        '#!/usr/bin/env bash',
        '# Container storage usage and cleanup for docker or podman.' + (dry ? ' Dry run: cleanup is printed, not executed.' : ''),
        runFn(dry),
        'CTR=$(command -v docker || command -v podman) || { echo "No docker or podman on this machine"; exit 1; }',
        'echo "Using: $CTR"'
      ];
      if (sel.parts.has('usage')) {
        lines.push('',
          'echo "== Usage breakdown =="',
          '"$CTR" system df -v 2>/dev/null | head -n 40',
          'du -sh /var/lib/docker /var/lib/containers 2>/dev/null');
      }
      if (sel.parts.has('prune')) {
        lines.push('', 'RUN "$CTR" system prune -af');
      }
      if (sel.parts.has('volumes')) {
        lines.push('', '# Deletes every volume no container references. This is data loss if you are wrong.', 'RUN "$CTR" volume prune -f');
      }
      return lines.join('\n');
    }
  });

  /* -------------------------------------------------- general troubleshooting */

  add({
    id: 'linux-triage',
    title: 'First five minutes on a sick machine',
    purposes: ['Linux', 'Troubleshooting', 'Reporting'],
    description: 'One triage pass: load against cores, memory, disks, top consumers, failed units, OOM kills, stuck processes and recent reboots.',
    requires: ROOT,
    keywords: 'linux triage health check uptime load nproc free df failed units oom dstate reboot first look sick server',
    options: [
      {
        id: 'parts', label: 'Sections', type: 'multi', wide: true, items: [
          { id: 'load', label: 'Load and cores', default: true },
          { id: 'memory', label: 'Memory and swap', default: true },
          { id: 'disk', label: 'Filesystems', default: true },
          { id: 'topcpu', label: 'Top CPU processes', default: true },
          { id: 'topmem', label: 'Top memory processes', default: true },
          { id: 'failed', label: 'Failed systemd units', default: true },
          { id: 'oom', label: 'OOM kills in the last two days', default: true },
          { id: 'dstate', label: 'Processes stuck on I/O', default: true },
          { id: 'reboots', label: 'Recent reboots and shutdowns', default: true }
        ]
      }
    ],
    build: sel => {
      const lines = ['#!/usr/bin/env bash', '# Quick health pass over the usual suspects.'];
      const section = (title, ...cmd) => lines.push('', 'echo "== ' + title + ' =="', ...cmd);
      if (sel.parts.has('load')) section('Load against cores', 'uptime', 'echo "cores: $(nproc)"');
      if (sel.parts.has('memory')) section('Memory and swap', 'free -h');
      if (sel.parts.has('disk')) section('Filesystems', 'df -hT -x tmpfs -x devtmpfs 2>/dev/null || df -hT');
      if (sel.parts.has('topcpu')) section('Top CPU', 'ps -eo pid,user,pcpu,pmem,comm --sort=-pcpu | head -n 11');
      if (sel.parts.has('topmem')) section('Top memory (RSS in KiB)', 'ps -eo pid,user,rss,pmem,comm --sort=-rss | head -n 11');
      if (sel.parts.has('failed')) section('Failed units', 'systemctl --failed --no-pager 2>/dev/null');
      if (sel.parts.has('oom')) section('OOM kills, last two days',
        "journalctl -k --since '-2 days' --no-pager 2>/dev/null | grep -iE 'out of memory|oom-kill' | tail -n 10");
      if (sel.parts.has('dstate')) section('Uninterruptible sleep (stuck on I/O)',
        "ps -eo state,pid,user,wchan:30,comm | awk 'NR==1 || $1 ~ /D/'");
      if (sel.parts.has('reboots')) section('Recent reboots', 'last -x reboot shutdown 2>/dev/null | head -n 6');
      return lines.join('\n');
    }
  });

  add({
    id: 'linux-service-debug',
    title: 'Troubleshoot a systemd service',
    purposes: ['Linux', 'Troubleshooting'],
    description: 'Status, recent journal, the unit file with overrides, and optionally a restart with a live log follow.',
    requires: ROOT,
    keywords: 'linux systemd service systemctl status journalctl unit failed restart follow logs cat override drop-in',
    options: [
      { id: 'svc', label: 'Service name', type: 'text', placeholder: 'nginx' },
      { id: 'since', label: 'Logs since', type: 'text', placeholder: '1 hour ago', value: '1 hour ago' },
      { id: 'lines', label: 'Maximum log lines', type: 'number', placeholder: '200', value: '200' },
      {
        id: 'parts', label: 'Include', type: 'multi', items: [
          { id: 'status', label: 'Status', default: true },
          { id: 'logs', label: 'Recent journal', default: true },
          { id: 'unit', label: 'Unit file and overrides', default: true },
          { id: 'restart', label: 'Restart the service and follow the log' }
        ]
      }
    ],
    build: sel => {
      const svc = sq(sel.svc) || 'nginx';
      const since = sq(sel.since) || '1 hour ago';
      const lines = [
        '#!/usr/bin/env bash',
        '# Everything systemd knows about one service.',
        "SERVICE='" + svc + "'"
      ];
      if (sel.parts.has('status')) lines.push('', 'systemctl status "$SERVICE" --no-pager --full');
      if (sel.parts.has('logs')) lines.push('',
        'echo "== Journal since ' + since + ' =="',
        'journalctl -u "$SERVICE" --since \'' + since + '\' -n ' + num(sel.lines, 200) + ' --no-pager');
      if (sel.parts.has('unit')) lines.push('',
        'echo "== Unit definition and overrides =="',
        'systemctl cat "$SERVICE" --no-pager 2>/dev/null');
      if (sel.parts.has('restart')) lines.push('',
        'systemctl restart "$SERVICE"',
        'journalctl -u "$SERVICE" -f');
      return lines.join('\n');
    }
  });

  add({
    id: 'linux-oom-memory',
    title: 'Memory pressure and OOM kills',
    purposes: ['Linux', 'Troubleshooting'],
    description: 'Who ate the memory: OOM killer history from the kernel log, the top resident consumers and the top swap users.',
    requires: ROOT,
    keywords: 'linux oom killer out of memory journalctl killed process rss swap vmswap top consumers memory leak',
    options: [
      { id: 'days', label: 'OOM history (days)', type: 'number', placeholder: '7', value: '7' },
      { id: 'top', label: 'Show top', type: 'number', placeholder: '15', value: '15' },
      {
        id: 'parts', label: 'Sections', type: 'multi', items: [
          { id: 'now', label: 'Current memory state', default: true },
          { id: 'oom', label: 'OOM killer history', default: true },
          { id: 'rss', label: 'Top memory consumers', default: true },
          { id: 'swap', label: 'Top swap users', default: true }
        ]
      }
    ],
    build: sel => {
      const lines = [
        '#!/usr/bin/env bash',
        '# Memory pressure investigation.',
        'DAYS=' + num(sel.days, 7),
        'TOP=' + num(sel.top, 15)
      ];
      if (sel.parts.has('now')) lines.push('', 'echo "== Current state =="', 'free -h');
      if (sel.parts.has('oom')) lines.push('',
        'echo "== OOM killer events in the last $DAYS days =="',
        'journalctl -k --since "-${DAYS} days" --no-pager 2>/dev/null | grep -iE \'killed process|out of memory|oom-kill\' | tail -n 20');
      if (sel.parts.has('rss')) lines.push('',
        'echo "== Top memory consumers (RSS in KiB) =="',
        'ps -eo pid,user,rss,pmem,comm --sort=-rss | head -n "$TOP"');
      if (sel.parts.has('swap')) lines.push('',
        'echo "== Top swap users (VmSwap in KiB) =="',
        'for f in /proc/[0-9]*/status; do',
        "    awk '/^Name/ { n = $2 } /^Pid/ { pid = $2 } /^VmSwap/ { if ($2 > 0) print $2, pid, n }' \"$f\" 2>/dev/null",
        'done | sort -rn | head -n "$TOP"');
      return lines.join('\n');
    }
  });

  add({
    id: 'linux-network-triage',
    title: 'Network triage',
    purposes: ['Linux', 'Network', 'Troubleshooting'],
    description: 'Addresses, routes, listening sockets, connection states, DNS configuration and an optional TCP reachability test without extra tools.',
    requires: ROOT + ' Uses ss and the bash /dev/tcp built-in, so nothing needs installing.',
    keywords: 'linux network ss -tulpn listening ports connection states ip route resolv dns dev tcp port test connectivity',
    options: [
      {
        id: 'parts', label: 'Sections', type: 'multi', items: [
          { id: 'addr', label: 'Addresses and routes', default: true },
          { id: 'listen', label: 'Listening sockets', default: true },
          { id: 'states', label: 'Connection state counts', default: true },
          { id: 'dns', label: 'DNS configuration', default: true },
          { id: 'test', label: 'TCP reachability test' }
        ]
      },
      { id: 'host', label: 'Test host', type: 'text', placeholder: 'intranet.contoso.com' },
      { id: 'port', label: 'Test port', type: 'number', placeholder: '443', value: '443' }
    ],
    build: sel => {
      const lines = ['#!/usr/bin/env bash', '# Network state in one pass.'];
      if (sel.parts.has('addr')) lines.push('',
        'echo "== Addresses =="', 'ip -brief addr', '',
        'echo "== Routes =="', 'ip route');
      if (sel.parts.has('listen')) lines.push('',
        'echo "== Listening sockets =="', 'ss -tulpn');
      if (sel.parts.has('states')) lines.push('',
        'echo "== TCP connection states =="',
        "ss -tan | awk 'NR > 1 { print $1 }' | sort | uniq -c | sort -rn");
      if (sel.parts.has('dns')) lines.push('',
        'echo "== DNS =="',
        'resolvectl status 2>/dev/null | head -n 20 || cat /etc/resolv.conf');
      if (sel.parts.has('test')) {
        const host = sq(sel.host) || 'intranet.contoso.com';
        lines.push('',
          "HOST='" + host + "'",
          'PORT=' + num(sel.port, 443),
          'echo "== Reachability of $HOST:$PORT =="',
          'getent hosts "$HOST" || echo "name does not resolve"',
          'if timeout 5 bash -c "cat < /dev/null > /dev/tcp/$HOST/$PORT" 2>/dev/null; then',
          '    echo "tcp $PORT open"',
          'else',
          '    echo "tcp $PORT closed or filtered"',
          'fi');
      }
      return lines.join('\n');
    }
  });

  add({
    id: 'linux-io-latency',
    title: 'Disk I/O and iowait',
    purposes: ['Linux', 'Files & Disk', 'Troubleshooting'],
    description: 'Is the machine slow because of the disks: iowait over time, per-device utilisation and the processes stuck waiting on I/O.',
    requires: ROOT + ' iostat comes from the sysstat package (dnf or apt install sysstat), the rest needs nothing.',
    keywords: 'linux iowait iostat vmstat disk latency utilisation await dstate stuck io slow storage sysstat',
    options: [
      {
        id: 'parts', label: 'Sections', type: 'multi', items: [
          { id: 'vmstat', label: 'iowait over five seconds', default: true },
          { id: 'iostat', label: 'Per-device utilisation', default: true },
          { id: 'dstate', label: 'Processes stuck on I/O', default: true },
          { id: 'writers', label: 'Top writers since start', default: true }
        ]
      },
      { id: 'top', label: 'Show top', type: 'number', placeholder: '10', value: '10' }
    ],
    build: sel => {
      const lines = ['#!/usr/bin/env bash', '# Disk latency investigation.', 'TOP=' + num(sel.top, 10)];
      if (sel.parts.has('vmstat')) lines.push('',
        'echo "== iowait (wa column) over five seconds =="', 'vmstat 1 5');
      if (sel.parts.has('iostat')) lines.push('',
        'echo "== Per-device utilisation =="',
        'iostat -xz 1 3 2>/dev/null || { echo "iostat missing, raw counters:"; cat /proc/diskstats; }');
      if (sel.parts.has('dstate')) lines.push('',
        'echo "== Uninterruptible sleep =="',
        "ps -eo state,pid,user,wchan:30,comm | awk 'NR==1 || $1 ~ /D/'");
      if (sel.parts.has('writers')) lines.push('',
        'echo "== Processes that wrote the most since they started =="',
        'for p in /proc/[0-9]*; do',
        "    wb=$(awk '/^write_bytes/ { print $2 }' \"$p/io\" 2>/dev/null)",
        '    [ -n "$wb" ] && [ "$wb" -gt 0 ] && printf \'%s %s %s\\n\' "$wb" "${p##*/}" "$(cat "$p/comm" 2>/dev/null)"',
        "done | sort -rn | head -n \"$TOP\" | awk '{ printf \"%10.1f MiB  pid %-7s %s\\n\", $1/1048576, $2, $3 }'");
      return lines.join('\n');
    }
  });

  add({
    id: 'linux-recent-changes',
    title: 'What changed on this machine',
    purposes: ['Linux', 'Troubleshooting', 'Audit'],
    description: 'The question after every "it worked yesterday": recent package installs and upgrades per family, plus freshly modified files in /etc.',
    requires: ROOT,
    keywords: 'linux recent changes rpm -qa --last dnf history dpkg.log apt history etc modified config what changed yesterday',
    options: [
      DISTRO,
      { id: 'days', label: 'Config changes in the last (days)', type: 'number', placeholder: '7', value: '7' },
      { id: 'top', label: 'Show top', type: 'number', placeholder: '25', value: '25' },
      {
        id: 'parts', label: 'Sections', type: 'multi', items: [
          { id: 'packages', label: 'Recent package activity', default: true },
          { id: 'etc', label: 'Recently modified files in /etc', default: true }
        ]
      }
    ],
    build: sel => {
      const rhel = [
        'echo "== Recently installed or updated packages =="',
        'rpm -qa --last | head -n "$TOP"',
        'echo',
        'echo "== Transaction history =="',
        'dnf history list 2>/dev/null | head -n 15'
      ];
      const debian = [
        'echo "== Recent dpkg activity =="',
        "grep -hE ' (install|upgrade|remove) ' /var/log/dpkg.log /var/log/dpkg.log.1 2>/dev/null | tail -n \"$TOP\""
      ];
      const lines = [
        '#!/usr/bin/env bash',
        '# Recent package and configuration changes.',
        'DAYS=' + num(sel.days, 7),
        'TOP=' + num(sel.top, 25),
        ''
      ];
      if (sel.parts.has('packages')) {
        if (sel.distro === 'rhel') lines.push(...rhel);
        else if (sel.distro === 'debian') lines.push(...debian);
        else {
          lines.push(
            '. /etc/os-release 2>/dev/null',
            'case "$ID ${ID_LIKE:-}" in',
            '    *rhel*|*fedora*|*centos*)');
          lines.push(...rhel.map(l => '        ' + l));
          lines.push('        ;;', '    *debian*|*ubuntu*)');
          lines.push(...debian.map(l => '        ' + l));
          lines.push('        ;;', 'esac');
        }
      }
      if (sel.parts.has('etc')) {
        lines.push('',
          'echo "== Files in /etc modified in the last $DAYS days =="',
          "find /etc -xdev -type f -mtime -\"$DAYS\" -printf '%TY-%Tm-%Td %TH:%TM  %p\\n' 2>/dev/null | sort -r | head -n \"$TOP\"");
      }
      return lines.join('\n');
    }
  });

  add({
    id: 'linux-auth-logins',
    title: 'Logins and failed logins',
    purposes: ['Linux', 'Security', 'Audit'],
    description: 'Who is on the machine, who signed in recently and which accounts are being brute forced, from wtmp, btmp and the sshd journal.',
    requires: ROOT + ' Works on both families, journalctl -t sshd matches the syslog tag either way.',
    keywords: 'linux who last lastb failed logins ssh brute force wtmp btmp journalctl sshd invalid user sessions',
    options: [
      { id: 'top', label: 'Show entries', type: 'number', placeholder: '20', value: '20' },
      { id: 'days', label: 'SSH failures in the last (days)', type: 'number', placeholder: '7', value: '7' },
      {
        id: 'parts', label: 'Sections', type: 'multi', items: [
          { id: 'now', label: 'Active sessions', default: true },
          { id: 'recent', label: 'Recent logins', default: true },
          { id: 'failed', label: 'Failed logins', default: true },
          { id: 'sources', label: 'Failed logins per source address', default: true }
        ]
      }
    ],
    build: sel => {
      const lines = [
        '#!/usr/bin/env bash',
        '# Login history and brute force check.',
        'TOP=' + num(sel.top, 20),
        'DAYS=' + num(sel.days, 7)
      ];
      if (sel.parts.has('now')) lines.push('', 'echo "== Active sessions =="', 'who');
      if (sel.parts.has('recent')) lines.push('',
        'echo "== Recent logins =="', 'last -a -n "$TOP" 2>/dev/null | head -n "$TOP"');
      if (sel.parts.has('failed')) lines.push('',
        'echo "== Failed logins (btmp) =="',
        'lastb -a -n "$TOP" 2>/dev/null || echo "btmp not readable, see the sshd section below"',
        '',
        'echo "== SSH failures in the last $DAYS days =="',
        'journalctl -t sshd --since "-${DAYS} days" --no-pager 2>/dev/null | grep -iE \'failed password|invalid user\' | tail -n "$TOP"');
      if (sel.parts.has('sources')) lines.push('',
        'echo "== Failure count per source address =="',
        'journalctl -t sshd --since "-${DAYS} days" --no-pager 2>/dev/null | grep -oE \'from ([0-9]{1,3}\\.){3}[0-9]{1,3}\' | sort | uniq -c | sort -rn | head -n "$TOP"');
      return lines.join('\n');
    }
  });

  ENTRIES.forEach(s => SCRIPTS.push(s));
})();

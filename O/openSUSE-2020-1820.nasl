#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1820.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(142522);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/20");

  script_cve_id("CVE-2020-14004");

  script_name(english:"openSUSE Security Update : icinga2 (openSUSE-2020-1820)");
  script_summary(english:"Check for the openSUSE-2020-1820 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for icinga2 fixes the following issues :

  - Info that since version 2.12.0 following security issue
    is fixed: prepare-dirs script allows for symlink attack
    in the icinga user context. boo#1172171 (CVE-2020-14004)

Update to 2.12.1 :

  - Bugfixes

  + Core

  - Fix crashes during config update #8348 #8345

  - Fix crash while removing a downtime #8228

  - Ensure the daemon doesn't get killed by logrotate #8170

  - Fix hangup during shutdown #8211

  - Fix a deadlock in Icinga DB #8168

  - Clean up zombie processes during reload #8376

  - Reduce check latency #8276

  + IDO

  - Prevent unnecessary IDO updates #8327 #8320

  - Commit IDO MySQL transactions earlier #8349

  - Make sure to insert IDO program status #8330

  - Improve IDO queue stats logging #8271 #8328 #8379

  + Misc

  - Ensure API connections are closed properly #8293

  - Prevent unnecessary notifications #8299

  - Don't skip null values of command arguments #8174

  - Fix Windows .exe version #8234

  - Reset Icinga check warning after successful config
    update #8189

Update to 2.12.0 :

  - Breaking changes

  - Deprecate Windows plugins in favor of our

  - PowerShell plugins #8071

  - Deprecate Livestatus #8051

  - Refuse acknowledging an already acknowledged checkable
    #7695

  - Config lexer: complain on EOF in heredocs, i.e.
    (((abc<EOF> #7541

  - Enhancements

  + Core

  - Implement new database backend: Icinga DB #7571

  - Re-send notifications previously suppressed by their
    time periods #7816

  + API

  - Host/Service: Add acknowledgement_last_change and
    next_update attributes #7881 #7534

  - Improve error message for POST queries #7681

  - /v1/actions/remove-comment: let users specify themselves
    #7646

  - /v1/actions/remove-downtime: let users specify
    themselves #7645

  - /v1/config/stages: Add 'activate' parameter #7535

  + CLI

  - Add pki verify command for better TLS certificate
    troubleshooting #7843

  - Add OpenSSL version to 'Build' section in --version
    #7833

  - Improve experience with 'Node Setup for
    Agents/Satellite' #7835

  + DSL

  - Add get_template() and get_templates() #7632

  - MacroProcessor::ResolveArguments(): skip null argument
    values #7567

  - Fix crash due to dependency apply rule with
    ignore_on_error and non-existing parent #7538

  - Introduce ternary operator (x ? y : z) #7442

  - LegacyTimePeriod: support specifying seconds #7439

  - Add support for Lambda Closures (() use(x) => x and ()
    use(x) => ( return x )) #7417

  + ITL

  - Add notemp parameter to oracle health #7748

  - Add extended checks options to snmp-interface command
    template #7602

  - Add file age check for Windows command definition #7540

  + Docs

  - Development: Update debugging instructions #7867

  - Add new API clients #7859

  - Clarify CRITICAL vs. UNKNOWN #7665

  - Explicitly explain how to disable freshness checks #7664

  - Update installation for RHEL/CentOS 8 and SLES 15 #7640

  - Add Powershell example to validate the certificate #7603

  + Misc

  - Don't send event::Heartbeat to unauthenticated peers
    #7747

  - OpenTsdbWriter: Add custom tag support #7357

  - Bugfixes

  + Core

  - Fix JSON-RPC crashes #7532 #7737

  - Fix zone definitions in zones #7546

  - Fix deadlock during start on OpenBSD #7739

  - Consider PENDING not a problem #7685

  - Fix zombie processes after reload #7606

  - Don't wait for checks to finish during reload #7894

  + Cluster

  - Fix segfault during heartbeat timeout with clients not
    yet signed #7970

  - Make the config update process mutually exclusive
    (Prevents file system race conditions) #7936

  - Fix check_timeout not being forwarded to agent command
    endpoints #7861

  - Config sync: Use a more friendly message when configs
    are equal and don't need a reload #7811

  - Fix open connections when agent waits for CA approval
    #7686

  - Consider a JsonRpcConnection alive on a single byte of
    TLS payload, not only on a whole message #7836

  - Send JsonRpcConnection heartbeat every 20s instead of
    10s #8102

  - Use JsonRpcConnection heartbeat only to update
    connection liveness (m_Seen) #8142

  - Fix TLS context not being updated on signed certificate
    messages on agents #7654

  + API

  - Close connections w/o successful TLS handshakes after
    10s #7809

  - Handle permission exceptions soon enough, returning 404
    #7528

  + SELinux

  - Fix safe-reload #7858

  - Allow direct SMTP notifications #7749

  + Windows

  - Terminate check processes with UNKNOWN state on timeout
    #7788

  - Ensure that log replay files are properly renamed #7767

  + Metrics

  - Graphite/OpenTSDB: Ensure that reconnect failure is
    detected #7765

  - Always send 0 as value for thresholds #7696

  + Scripts

  - Fix notification scripts to stay compatible with Dash
    #7706

  - Fix bash line continuation in mail-host-notification.sh
    #7701

  - Fix notification scripts string comparison #7647

  - Service and host mail-notifications: Add line-breaks to
    very long output #6822

  - Set correct UTF-8 email subject header (RFC1342) #6369

  + Misc

  - DSL: Fix segfault due to passing null as custom function
    to Array#(sort,map,reduce,filter,any,all)() #8053

  - CLI: pki save-cert: allow to specify --key and --cert
    for backwards compatibility #7995

  - Catch exception when trusted cert is not readable during
    node setup on agent/satellite #7838

  - CheckCommand ssl: Fix wrong parameter -N #7741

  - Code quality fixes

  - Small documentation fixes

  - Update to 2.11.5 Version 2.11.5 fixes file system race
    conditions in the config update process occurring in
    large HA environments and improves the cluster
    connection liveness mechanisms.

  - Bugfixes

  + Make the config update process mutually exclusive
    (Prevents file system race conditions) #8093

  + Consider a JsonRpcConnection alive on a single byte of
    TLS payload, not only on a whole message #8094

  + Send JsonRpcConnection heartbeat every 20s instead of
    10s #8103

  + Use JsonRpcConnection heartbeat only to update
    connection liveness (m_Seen) #8097

  - Update to 2.11.4 Version 2.11.4 fixes a crash during a
    heartbeat timeout with clients not yet signed. It also
    resolves an issue with endpoints not reconnecting after
    a reload/deploy, which caused a lot of UNKNOWN states.

  - Bugfixes

  + Cluster

  - Fix segfault during heartbeat timeout with clients not
    yet signed #7997

  - Fix endpoints not reconnecting after reload (UNKNOWN
    hosts/services after reload) #8043

  + Setup

  - Fix exception on trusted cert not readable during node
    setup #8044

  - prepare-dirs: Only set permissions during directory
    creation #8046

  + DSL

  - Fix segfault on missing compare function in Array
    functions (sort, map, reduce, filter, any, all) #8054

  - Update to 2.11.3

  - Bugfixes

  - Cluster Fix JSON-RPC crashes (#7532) in large
    environments: #7846 #7848 #7849

  - Set minimum require boost version to 1.66

  - Fix boo#1159869 Permission error when use the icinga cli
    wizard. 

  - BuildRequire pkgconfig(libsystemd) instead of
    systemd-devel: Aloow OBS to shortcut through the -mini
    flavors.

  - Update to 2.11.2 This release fixes a problem where the
    newly introduced config sync 'check-change-then-reload'
    functionality could cause endless reload loops with
    agents. The most visible parts are failing command
    endpoint checks with 'not connected' UNKNOWN state. Only
    applies to HA enabled zones with 2 masters and/or 2
    satellites.

  - Bugfixes

  - Cluster Config Sync

  - Config sync checksum change detection may not work
    within high load HA clusters #7565

  - Update to 2.11.1 This release fixes a hidden long
    lasting bug unveiled with 2.11 and distributed setups.
    If you are affected by agents/satellites not accepting
    configuration anymore, or not reloading, please upgrade.

  - Bugfixes

  - Cluster Config Sync

  - Never accept authoritative config markers from other
    instances #7552

  - This affects setups where agent/satellites are newer
    than the config master, e.g. satellite/agent=2.11.0,
    master=2.10.

  - Configuration

  - Error message for command_endpoint should hint that zone
    is not set #7514

  - Global variable 'ActiveStageOverride' has been set
    implicitly via 'ActiveStageOverride ... #7521

  - Documentation

  - Docs: Add upgrading/troubleshooting details for repos,
    config sync, agents #7526

  - Explain repository requirements for 2.11:
    https://icinga.com/docs/icinga2/latest/doc/16-upgrading-
    icinga-2/#added-boost-166

  - command_endpoint objects require a zone:
    https://icinga.com/docs/icinga2/latest/doc/16-upgrading-
    icinga-2/#agent-hosts-with-command-endpoint-require-a-zo
    ne

  - Zones declared in zones.d are not loaded anymore:
    https://icinga.com/docs/icinga2/latest/doc/16-upgrading-
    icinga-2/#config-sync-zones-in-zones

  - Update to 2.11.0

  - Core

  - Rewrite Network Stack (cluster, REST API) based on Boost
    Asio, Beast, Coroutines

  - Technical concept: #7041

  - Requires package updates: Boost >1.66 (either from
    packages.icinga.com, EPEL or backports). SLES11 & Ubuntu
    14 are EOL.

  - Require TLS 1.2 and harden default cipher list

  - Improved Reload Handling (umbrella process, now 3
    processes at runtime)

  - Support running Icinga 2 in (Docker) containers natively
    in foreground

  - Quality: Use Modern JSON for C++ library instead of YAJL
    (dead project)

  - Quality: Improve handling of invalid UTF8 strings

  - API

  - Fix crashes on Linux, Unix and Windows from Nessus scans
    #7431

  - Locks and stalled waits are fixed with the core rewrite
    in #7071

  - schedule-downtime action supports all_services for host
    downtimes

  - Improve storage handling for runtime created objects in
    the _api package

  - Cluster

  - HA aware features & improvements for failover handling
    #2941 #7062

  - Improve cluster config sync with staging #6716

  - Fixed that same downtime/comment objects would be synced
    again in a cluster loop #7198

  - Checks & Notifications

  - Ensure that notifications during a restart are sent

  - Immediately notify about a problem after leaving a
    downtime and still NOT-OK

  - Improve reload handling and wait for features/metrics

  - Store notification command results and sync them in HA
    enabled zones #6722

  - DSL/Configuration

  - Add getenv() function

  - Fix TimePeriod range support over midnight

  - concurrent_checks in the Checker feature has no effect,
    use the global MaxConcurrentChecks constant instead

  - CLI

  - Permissions: node wizard/setup, feature, api setup now
    run in the Icinga user context, not root

  - ca list shows pending CSRs by default, ca remove/restore
    allow to delete signing requests

  - ITL

  - Add new commands and missing attributes

  - Windows

  - Update bundled NSClient++ to 0.5.2.39

  - Refine agent setup wizard & update requirements to .NET
    4.6

  - Documentation

  - Service Monitoring: How to create plugins by example,
    check commands and a modern version of the supported
    plugin API with best practices

  - Features: Better structure on metrics, and supported
    features

  - Technical Concepts: TLS Network IO, Cluster Feature HA,
    Cluster Config Sync

  - Development: Rewritten for better debugging and
    development experience for contributors including a
    style guide. Add nightly build setup instructions.

  - Packaging: INSTALL.md was integrated into the
    Development chapter, being available at
    https://icinga.com/docs too.

  - Update to 2.10.6

  - Bugfixes

  - Fix el7 not loading ECDHE cipher suites #7247

  - update to 2.10.5

  - Core

  - Fix crashes with logrotate signals #6737 (thanks Elias
    Ohm)

  - API

  - Fix crashes and problems with permission filters from
    recent Namespace introduction #6785 (thanks Elias Ohm)
    #6874 (backported from 2.11)

  - Reduce log spam with locked connections (real fix is the
    network stack rewrite in 2.11) #6877

  - Cluster

  - Fix problems with replay log rotation and storage #6932
    (thanks Peter Eckel)

  - IDO DB

  - Fix that reload shutdown deactivates hosts and
    hostgroups (introduced in 2.9) #7157

  - Documentation

  - Improve the REST API chapter: Unix timestamp handling,
    filters, unify POST requests with filters in the body

  - Better layout for the features chapter, specifically
    metrics and events

  - Split object types into monitoring, runtime, features

  - Add technical concepts for cluster messages"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://icinga.com/docs"
  );
  # https://icinga.com/docs/icinga2/latest/doc/16-upgrading-icinga-2/#added-boost-166
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?523cf707"
  );
  # https://icinga.com/docs/icinga2/latest/doc/16-upgrading-icinga-2/#agent-hosts-with-command-endpoint-require-a-zone
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a1dc9ab8"
  );
  # https://icinga.com/docs/icinga2/latest/doc/16-upgrading-icinga-2/#config-sync-zones-in-zones
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7574676"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected icinga2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14004");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga2-bin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga2-ido-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga2-ido-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga2-ido-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga2-ido-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nano-icinga2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim-icinga2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.1|SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1 / 15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"icinga2-2.12.1-lp151.2.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icinga2-bin-2.12.1-lp151.2.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icinga2-bin-debuginfo-2.12.1-lp151.2.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icinga2-common-2.12.1-lp151.2.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icinga2-debuginfo-2.12.1-lp151.2.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icinga2-debugsource-2.12.1-lp151.2.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icinga2-ido-mysql-2.12.1-lp151.2.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icinga2-ido-mysql-debuginfo-2.12.1-lp151.2.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icinga2-ido-pgsql-2.12.1-lp151.2.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icinga2-ido-pgsql-debuginfo-2.12.1-lp151.2.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nano-icinga2-2.12.1-lp151.2.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vim-icinga2-2.12.1-lp151.2.3.4") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"icinga2-2.12.1-lp152.3.3.3") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"icinga2-bin-2.12.1-lp152.3.3.3") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"icinga2-bin-debuginfo-2.12.1-lp152.3.3.3") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"icinga2-common-2.12.1-lp152.3.3.3") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"icinga2-debuginfo-2.12.1-lp152.3.3.3") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"icinga2-debugsource-2.12.1-lp152.3.3.3") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"icinga2-ido-mysql-2.12.1-lp152.3.3.3") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"icinga2-ido-mysql-debuginfo-2.12.1-lp152.3.3.3") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"icinga2-ido-pgsql-2.12.1-lp152.3.3.3") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"icinga2-ido-pgsql-debuginfo-2.12.1-lp152.3.3.3") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nano-icinga2-2.12.1-lp152.3.3.3") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"vim-icinga2-2.12.1-lp152.3.3.3") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icinga2 / icinga2-bin / icinga2-bin-debuginfo / icinga2-common / etc");
}

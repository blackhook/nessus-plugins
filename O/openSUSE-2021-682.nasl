#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-682.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149549);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/20");

  script_cve_id("CVE-2021-21309", "CVE-2021-29477", "CVE-2021-29478");

  script_name(english:"openSUSE Security Update : redis (openSUSE-2021-682)");
  script_summary(english:"Check for the openSUSE-2021-682 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for redis fixes the following issues :

redis 6.0.13

  - CVE-2021-29477: Integer overflow in STRALGO LCS command
    (boo#1185729)

  - CVE-2021-29478: Integer overflow in COPY command for
    large intsets (boo#1185730)

  - Cluster: Skip unnecessary check which may prevent
    failure detection

  - Fix performance regression in BRPOP on Redis 6.0

  - Fix edge-case when a module client is unblocked

redis 6.0.12 :

  - Fix compilation error on non-glibc systems if jemalloc
    is not used

redis 6.0.11 :

  - CVE-2021-21309: Avoid 32-bit overflows when
    proto-max-bulk-len is set high (boo#1182657)

  - Fix handling of threaded IO and CLIENT PAUSE (failover),
    could lead to data loss or a crash

  - Fix the selection of a random element from large hash
    tables

  - Fix broken protocol in client tracking
    tracking-redir-broken message

  - XINFO able to access expired keys on a replica

  - Fix broken protocol in redis-benchmark when used with -a
    or --dbnum 

  - Avoid assertions (on older kernels) when testing arm64
    CoW bug

  - CONFIG REWRITE should honor umask settings

  - Fix firstkey,lastkey,step in COMMAND command for some
    commands

  - RM_ZsetRem: Delete key if empty, the bug could leave
    empty zset keys 

redis 6.0.10 :

Command behavior changes :

  - SWAPDB invalidates WATCHed keys (#8239)

  - SORT command behaves differently when used on a writable
    replica (#8283)

  - EXISTS should not alter LRU (#8016) In Redis 5.0 and 6.0
    it would have touched the LRU/LFU of the key.

  - OBJECT should not reveal logically expired keys (#8016)
    Will now behave the same TYPE or any other non-DEBUG
    command.

  - GEORADIUS[BYMEMBER] can fail with -OOM if Redis is over
    the memory limit (#8107)

Other behavior changes :

  - Sentinel: Fix missing updates to the config file after
    SENTINEL SET command (#8229)

  - CONFIG REWRITE is atomic and safer, but requires write
    access to the config file's folder (#7824, #8051) This
    change was already present in 6.0.9, but was missing
    from the release notes.

Bug fixes with compatibility implications (bugs introduced in Redis
6.0) :

  - Fix RDB CRC64 checksum on big-endian systems (#8270) If
    you're using big-endian please consider the
    compatibility implications with RESTORE, replication and
    persistence.

  - Fix wrong order of key/value in Lua's map response
    (#8266) If your scripts use redis.setresp() or return a
    map (new in Redis 6.0), please consider the
    implications.

Bug fixes :

  - Fix an issue where a forked process deletes the parent's
    pidfile (#8231)

  - Fix crashes when enabling io-threads-do-reads (#8230)

  - Fix a crash in redis-cli after executing cluster backup
    (#8267)

  - Handle output buffer limits for module blocked clients
    (#8141) Could result in a module sending reply to a
    blocked client to go beyond the limit.

  - Fix setproctitle related crashes. (#8150, #8088) Caused
    various crashes on startup, mainly on Apple M1 chips or
    under instrumentation.

  - Backup/restore cluster mode keys to slots map for
    repl-diskless-load=swapdb (#8108) In cluster mode with
    repl-diskless-load, when loading failed, slot map
    wouldn't have been restored.

  - Fix oom-score-adj-values range, and bug when used in
    config file (#8046) Enabling setting this in the config
    file in a line after enabling it, would have been buggy.

  - Reset average ttl when empty databases (#8106) Just
    causing misleading metric in INFO

  - Disable rehash when Redis has child process (#8007) This
    could have caused excessive CoW during BGSAVE,
    replication or AOFRW.

  - Further improved ACL algorithm for picking categories
    (#7966) Output of ACL GETUSER is now more similar to the
    one provided by ACL SETUSER.

  - Fix bug with module GIL being released prematurely
    (#8061) Could in theory (and rarely) cause
    multi-threaded modules to corrupt memory.

  - Reduce effect of client tracking causing feedback loop
    in key eviction (#8100)

  - Fix cluster access to unaligned memory (SIGBUS on old
    ARM) (#7958)

  - Fix saving of strings larger than 2GB into RDB files
    (#8306)

Additional improvements :

  - Avoid wasteful transient memory allocation in certain
    cases (#8286, #5954)

Platform / toolchain support related improvements :

  - Fix crash log registers output on ARM. (#8020)

  - Add a check for an ARM64 Linux kernel bug (#8224) Due to
    the potential severity of this issue, Redis will print
    log warning on startup.

  - Raspberry build fix. (#8095)

New configuration options :

  - oom-score-adj-values config can now take absolute values
    (besides relative ones) (#8046)

Module related fixes :

  - Moved RMAPI_FUNC_SUPPORTED so that it's usable (#8037)

  - Improve timer accuracy (#7987)

  - Allow '\0' inside of result of RM_CreateStringPrintf
    (#6260)

redis 6.0.9 :

  - potential heap overflow when using a heap allocator
    other than jemalloc or glibc's malloc. Does not affect
    the openSUSE package - boo#1178205 

  - Memory reporting of clients argv

  - Add redis-cli control on raw format line delimiter

  - Add redis-cli support for rediss:// -u prefix

  - WATCH no longer ignores keys which have expired for
    MULTI/EXEC

  - Correct OBJECT ENCODING response for stream type

  - Allow blocked XREAD on a cluster replica

  - TLS: Do not require CA config if not used

  - multiple bug fixes

  - Additions to modules API

redis 6.0.8 (jsc#PM-1615, jsc#PM-1622, jsc#PM-1681, jsc#ECO-2417,
jsc#ECO-2867, jsc#PM-1547, jsc#CAPS-56, jsc#SLE-11578, 
jsc#SLE-12821) :

  - bug fixes when using with Sentinel

  - bug fixes when using CONFIG REWRITE

  - Remove THP warning when set to madvise

  - Allow EXEC with read commands on readonly replica in
    cluster

  - Add masters/replicas options to redis-cli --cluster call
    command

  - includes changes from 6.0.7 :

  - CONFIG SET could hung the client when arrives during
    RDB/ROF loading

  - LPOS command when RANK is greater than matches responded
    with broken protocol

  - Add oom-score-adj configuration option to control Linux
    OOM killer

  - Show IO threads statistics and status in INFO output

  - Add optional tls verification mode (see
    tls-auth-clients)

redis 6.0.6 :

  - Fix crash when enabling CLIENT TRACKING with prefix

  - EXEC always fails with EXECABORT and multi-state is
    cleared

  - RESTORE ABSTTL won't store expired keys into the db

  - redis-cli better handling of non-pritable key names

  - TLS: Ignore client cert when tls-auth-clients off

  - Tracking: fix invalidation message on flush

  - Notify systemd on Sentinel startup

  - Fix crash on a misuse of STRALGO

  - Few fixes in module API

  - Fix a few rare leaks (STRALGO error misuse, Sentinel)

  - Fix a possible invalid access in defrag of scripts

  - Add LPOS command to search in a list

  - Use user+pass for MIGRATE in redis-cli and
    redis-benchmark in cluster mode

  - redis-cli support TLS for --pipe, --rdb and --replica
    options

  - TLS: Session caching configuration support

redis 6.0.5 :

  - Fix handling of speical chars in ACL LOAD

  - Make Redis Cluster more robust about operation errors
    that may lead to two clusters to mix together

  - Revert the sendfile() implementation of RDB transfer

  - Fix TLS certificate loading for chained certificates

  - Fix AOF rewirting of KEEPTTL SET option

  - Fix MULTI/EXEC behavior during -BUSY script errors"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://jira.suse.com/browse/ECO-2417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://jira.suse.com/browse/ECO-2867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://jira.suse.com/browse/PM-1547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://jira.suse.com/browse/PM-1615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://jira.suse.com/browse/PM-1622"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://jira.suse.com/browse/PM-1681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://jira.suse.com/browse/SLE-11578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://jira.suse.com/browse/SLE-12821"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected redis packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:redis-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:redis-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"redis-6.0.13-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"redis-debuginfo-6.0.13-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"redis-debugsource-6.0.13-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "redis / redis-debuginfo / redis-debugsource");
}

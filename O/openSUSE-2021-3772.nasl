#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:3772-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155697);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/24");

  script_cve_id(
    "CVE-2021-32626",
    "CVE-2021-32627",
    "CVE-2021-32628",
    "CVE-2021-32672",
    "CVE-2021-32675",
    "CVE-2021-32687",
    "CVE-2021-32762",
    "CVE-2021-41099"
  );

  script_name(english:"openSUSE 15 Security Update : redis (openSUSE-SU-2021:3772-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has a package installed that is affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:3772-1 advisory.

  - Redis is an open source, in-memory database that persists on disk. In affected versions specially crafted
    Lua scripts executing in Redis can cause the heap-based Lua stack to be overflowed, due to incomplete
    checks for this condition. This can result with heap corruption and potentially remote code execution.
    This problem exists in all versions of Redis with Lua scripting support, starting from 2.6. The problem is
    fixed in versions 6.2.6, 6.0.16 and 5.0.14. For users unable to update an additional workaround to
    mitigate the problem without patching the redis-server executable is to prevent users from executing Lua
    scripts. This can be done using ACL to restrict EVAL and EVALSHA commands. (CVE-2021-32626)

  - Redis is an open source, in-memory database that persists on disk. In affected versions an integer
    overflow bug in Redis can be exploited to corrupt the heap and potentially result with remote code
    execution. The vulnerability involves changing the default proto-max-bulk-len and client-query-buffer-
    limit configuration parameters to very large values and constructing specially crafted very large stream
    elements. The problem is fixed in Redis 6.2.6, 6.0.16 and 5.0.14. For users unable to upgrade an
    additional workaround to mitigate the problem without patching the redis-server executable is to prevent
    users from modifying the proto-max-bulk-len configuration parameter. This can be done using ACL to
    restrict unprivileged users from using the CONFIG SET command. (CVE-2021-32627)

  - Redis is an open source, in-memory database that persists on disk. An integer overflow bug in the ziplist
    data structure used by all versions of Redis can be exploited to corrupt the heap and potentially result
    with remote code execution. The vulnerability involves modifying the default ziplist configuration
    parameters (hash-max-ziplist-entries, hash-max-ziplist-value, zset-max-ziplist-entries or zset-max-
    ziplist-value) to a very large value, and then constructing specially crafted commands to create very
    large ziplists. The problem is fixed in Redis versions 6.2.6, 6.0.16, 5.0.14. An additional workaround to
    mitigate the problem without patching the redis-server executable is to prevent users from modifying the
    above configuration parameters. This can be done using ACL to restrict unprivileged users from using the
    CONFIG SET command. (CVE-2021-32628)

  - Redis is an open source, in-memory database that persists on disk. When using the Redis Lua Debugger,
    users can send malformed requests that cause the debugger's protocol parser to read data beyond the actual
    buffer. This issue affects all versions of Redis with Lua debugging support (3.2 or newer). The problem is
    fixed in versions 6.2.6, 6.0.16 and 5.0.14. (CVE-2021-32672)

  - Redis is an open source, in-memory database that persists on disk. When parsing an incoming Redis Standard
    Protocol (RESP) request, Redis allocates memory according to user-specified values which determine the
    number of elements (in the multi-bulk header) and size of each element (in the bulk header). An attacker
    delivering specially crafted requests over multiple connections can cause the server to allocate
    significant amount of memory. Because the same parsing mechanism is used to handle authentication
    requests, this vulnerability can also be exploited by unauthenticated users. The problem is fixed in Redis
    versions 6.2.6, 6.0.16 and 5.0.14. An additional workaround to mitigate this problem without patching the
    redis-server executable is to block access to prevent unauthenticated users from connecting to Redis. This
    can be done in different ways: Using network access control tools like firewalls, iptables, security
    groups, etc. or Enabling TLS and requiring users to authenticate using client side certificates.
    (CVE-2021-32675)

  - Redis is an open source, in-memory database that persists on disk. An integer overflow bug affecting all
    versions of Redis can be exploited to corrupt the heap and potentially be used to leak arbitrary contents
    of the heap or trigger remote code execution. The vulnerability involves changing the default set-max-
    intset-entries configuration parameter to a very large value and constructing specially crafted commands
    to manipulate sets. The problem is fixed in Redis versions 6.2.6, 6.0.16 and 5.0.14. An additional
    workaround to mitigate the problem without patching the redis-server executable is to prevent users from
    modifying the set-max-intset-entries configuration parameter. This can be done using ACL to restrict
    unprivileged users from using the CONFIG SET command. (CVE-2021-32687)

  - Redis is an open source, in-memory database that persists on disk. The redis-cli command line tool and
    redis-sentinel service may be vulnerable to integer overflow when parsing specially crafted large multi-
    bulk network replies. This is a result of a vulnerability in the underlying hiredis library which does not
    perform an overflow check before calling the calloc() heap allocation function. This issue only impacts
    systems with heap allocators that do not perform their own overflow checks. Most modern systems do and are
    therefore not likely to be affected. Furthermore, by default redis-sentinel uses the jemalloc allocator
    which is also not vulnerable. The problem is fixed in Redis versions 6.2.6, 6.0.16 and 5.0.14.
    (CVE-2021-32762)

  - Redis is an open source, in-memory database that persists on disk. An integer overflow bug in the
    underlying string library can be used to corrupt the heap and potentially result with denial of service or
    remote code execution. The vulnerability involves changing the default proto-max-bulk-len configuration
    parameter to a very large value and constructing specially crafted network payloads or commands. The
    problem is fixed in Redis versions 6.2.6, 6.0.16 and 5.0.14. An additional workaround to mitigate the
    problem without patching the redis-server executable is to prevent users from modifying the proto-max-
    bulk-len configuration parameter. This can be done using ACL to restrict unprivileged users from using the
    CONFIG SET command. (CVE-2021-41099)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191299");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191300");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191302");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191303");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191306");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OTFIHYYQFTTATMKJQIWNX7F7WKXQXYDB/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1d94781");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32626");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32627");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32628");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32672");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32675");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32687");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32762");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-41099");
  script_set_attribute(attribute:"solution", value:
"Update the affected redis package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32762");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:redis");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'redis-6.0.14-6.8.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'redis');
}

#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5001. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154948);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/06");

  script_cve_id(
    "CVE-2021-32626",
    "CVE-2021-32627",
    "CVE-2021-32628",
    "CVE-2021-32672",
    "CVE-2021-32675",
    "CVE-2021-32687",
    "CVE-2021-32761",
    "CVE-2021-32762",
    "CVE-2021-41099"
  );

  script_name(english:"Debian DSA-5001-1 : redis - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5001 advisory.

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

  - Redis is an in-memory database that persists on disk. A vulnerability involving out-of-bounds read and
    integer overflow to buffer overflow exists starting with version 2.2 and prior to versions 5.0.13, 6.0.15,
    and 6.2.5. On 32-bit systems, Redis `*BIT*` command are vulnerable to integer overflow that can
    potentially be exploited to corrupt the heap, leak arbitrary heap contents or trigger remote code
    execution. The vulnerability involves changing the default `proto-max-bulk-len` configuration parameter to
    a very large value and constructing specially crafted commands bit commands. This problem only affects
    Redis on 32-bit platforms, or compiled as a 32-bit binary. Redis versions 5.0.`3m 6.0.15, and 6.2.5
    contain patches for this issue. An additional workaround to mitigate the problem without patching the
    `redis-server` executable is to prevent users from modifying the `proto-max-bulk-len` configuration
    parameter. This can be done using ACL to restrict unprivileged users from using the CONFIG SET command.
    (CVE-2021-32761)

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
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/redis");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-5001");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32626");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32627");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32628");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32672");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32675");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32687");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32761");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32762");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41099");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/redis");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/redis");
  script_set_attribute(attribute:"solution", value:
"Upgrade the redis packages.

For the stable distribution (bullseye), these problems have been fixed in version 5");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32762");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:redis-sentinel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:redis-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:redis-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+|^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0 / 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'redis', 'reference': '5:5.0.14-1+deb10u1'},
    {'release': '10.0', 'prefix': 'redis-sentinel', 'reference': '5:5.0.14-1+deb10u1'},
    {'release': '10.0', 'prefix': 'redis-server', 'reference': '5:5.0.14-1+deb10u1'},
    {'release': '10.0', 'prefix': 'redis-tools', 'reference': '5:5.0.14-1+deb10u1'},
    {'release': '11.0', 'prefix': 'redis', 'reference': '5:6.0.16-1+deb11u1'},
    {'release': '11.0', 'prefix': 'redis-sentinel', 'reference': '5:6.0.16-1+deb11u1'},
    {'release': '11.0', 'prefix': 'redis-server', 'reference': '5:6.0.16-1+deb11u1'},
    {'release': '11.0', 'prefix': 'redis-tools', 'reference': '5:6.0.16-1+deb11u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'redis / redis-sentinel / redis-server / redis-tools');
}

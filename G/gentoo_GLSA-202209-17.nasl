#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202209-17.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(165541);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/29");

  script_cve_id(
    "CVE-2021-32626",
    "CVE-2021-32627",
    "CVE-2021-32628",
    "CVE-2021-32672",
    "CVE-2021-32675",
    "CVE-2021-32687",
    "CVE-2021-32761",
    "CVE-2021-32762",
    "CVE-2021-41099",
    "CVE-2022-24735",
    "CVE-2022-24736",
    "CVE-2022-31144",
    "CVE-2022-33105",
    "CVE-2022-35951"
  );

  script_name(english:"GLSA-202209-17 : Redis: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202209-17 (Redis: Multiple Vulnerabilities)

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

  - Redis is an in-memory database that persists on disk. By exploiting weaknesses in the Lua script execution
    environment, an attacker with access to Redis prior to version 7.0.0 or 6.2.7 can inject Lua code that
    will execute with the (potentially higher) privileges of another Redis user. The Lua script execution
    environment in Redis provides some measures that prevent a script from creating side effects that persist
    and can affect the execution of the same, or different script, at a later time. Several weaknesses of
    these measures have been publicly known for a long time, but they had no security impact as the Redis
    security model did not endorse the concept of users or privileges. With the introduction of ACLs in Redis
    6.0, these weaknesses can be exploited by a less privileged users to inject Lua code that will execute at
    a later time, when a privileged user executes a Lua script. The problem is fixed in Redis versions 7.0.0
    and 6.2.7. An additional workaround to mitigate this problem without patching the redis-server executable,
    if Lua scripting is not being used, is to block access to `SCRIPT LOAD` and `EVAL` commands using ACL
    rules. (CVE-2022-24735)

  - Redis is an in-memory database that persists on disk. Prior to versions 6.2.7 and 7.0.0, an attacker
    attempting to load a specially crafted Lua script can cause NULL pointer dereference which will result
    with a crash of the redis-server process. The problem is fixed in Redis versions 7.0.0 and 6.2.7. An
    additional workaround to mitigate this problem without patching the redis-server executable, if Lua
    scripting is not being used, is to block access to `SCRIPT LOAD` and `EVAL` commands using ACL rules.
    (CVE-2022-24736)

  - Redis is an in-memory database that persists on disk. A specially crafted `XAUTOCLAIM` command on a stream
    key in a specific state may result with heap overflow, and potentially remote code execution. This problem
    affects versions on the 7.x branch prior to 7.0.4. The patch is released in version 7.0.4.
    (CVE-2022-31144)

  - Redis v7.0 was discovered to contain a memory leak via the component streamGetEdgeID. (CVE-2022-33105)

  - Redis is an in-memory database that persists on disk. Versions 7.0.0 and above, prior to 7.0.5 are
    vulnerable to an Integer Overflow. Executing an `XAUTOCLAIM` command on a stream key in a specific state,
    with a specially crafted `COUNT` argument may cause an integer overflow, a subsequent heap overflow, and
    potentially lead to remote code execution. This has been patched in Redis version 7.0.5. No known
    workarounds exist. (CVE-2022-35951)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202209-17");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=803302");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=816282");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=841404");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=856040");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=859181");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=872278");
  script_set_attribute(attribute:"solution", value:
"All Redis users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-db/redis-7.0.5");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32762");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-35951");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:redis");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : "dev-db/redis",
    'unaffected' : make_list("ge 7.0.5", "lt 7.0.0"),
    'vulnerable' : make_list("lt 7.0.5")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}

# This plugin has a different number of unaffected and vulnerable versions for
# one or more packages. To ensure proper detection, a separate line should be 
# used for each fixed/vulnerable version pair.

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Redis");
}

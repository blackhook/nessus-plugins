#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-3918.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154236);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/19");

  script_cve_id(
    "CVE-2021-32626",
    "CVE-2021-32627",
    "CVE-2021-32628",
    "CVE-2021-32675",
    "CVE-2021-32687",
    "CVE-2021-41099"
  );

  script_name(english:"Oracle Linux 8 : redis:5 (ELSA-2021-3918)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-3918 advisory.

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

  - Redis is an open source, in-memory database that persists on disk. An integer overflow bug in the
    underlying string library can be used to corrupt the heap and potentially result with denial of service or
    remote code execution. The vulnerability involves changing the default proto-max-bulk-len configuration
    parameter to a very large value and constructing specially crafted network payloads or commands. The
    problem is fixed in Redis versions 6.2.6, 6.0.16 and 5.0.14. An additional workaround to mitigate the
    problem without patching the redis-server executable is to prevent users from modifying the proto-max-
    bulk-len configuration parameter. This can be done using ACL to restrict unprivileged users from using the
    CONFIG SET command. (CVE-2021-41099)

  - Redis is an open source, in-memory database that persists on disk. An integer overflow bug affecting all
    versions of Redis can be exploited to corrupt the heap and potentially be used to leak arbitrary contents
    of the heap or trigger remote code execution. The vulnerability involves changing the default set-max-
    intset-entries configuration parameter to a very large value and constructing specially crafted commands
    to manipulate sets. The problem is fixed in Redis versions 6.2.6, 6.0.16 and 5.0.14. An additional
    workaround to mitigate the problem without patching the redis-server executable is to prevent users from
    modifying the set-max-intset-entries configuration parameter. This can be done using ACL to restrict
    unprivileged users from using the CONFIG SET command. (CVE-2021-32687)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-3918.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected redis, redis-devel and / or redis-doc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32626");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:redis-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:redis-doc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/redis');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module redis:5');
if ('5' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module redis:' + module_ver);

var appstreams = {
    'redis:5': [
      {'reference':'redis-5.0.3-5.module+el8.4.0+20382+7694043a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'redis-5.0.3-5.module+el8.4.0+20382+7694043a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'redis-devel-5.0.3-5.module+el8.4.0+20382+7694043a', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'redis-devel-5.0.3-5.module+el8.4.0+20382+7694043a', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'redis-doc-5.0.3-5.module+el8.4.0+20382+7694043a', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var release = NULL;
      var sp = NULL;
      var cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && release) {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module redis:5');

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'redis / redis-devel / redis-doc');
}

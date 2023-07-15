#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2023:3577.
##

include('compat.inc');

if (description)
{
  script_id(177604);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/25");

  script_cve_id(
    "CVE-2023-31124",
    "CVE-2023-31130",
    "CVE-2023-31147",
    "CVE-2023-32067"
  );
  script_xref(name:"RLSA", value:"2023:3577");

  script_name(english:"Rocky Linux 9 : nodejs:18 (RLSA-2023:3577)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2023:3577 advisory.

  - c-ares is an asynchronous resolver library. When cross-compiling c-ares and using the autotools build
    system, CARES_RANDOM_FILE will not be set, as seen when cross compiling aarch64 android. This will
    downgrade to using rand() as a fallback which could allow an attacker to take advantage of the lack of
    entropy by not using a CSPRNG. This issue was patched in version 1.19.1. (CVE-2023-31124)

  - c-ares is an asynchronous resolver library. ares_inet_net_pton() is vulnerable to a buffer underflow for
    certain ipv6 addresses, in particular 0::00:00:00/2 was found to cause an issue. C-ares only uses this
    function internally for configuration purposes which would require an administrator to configure such an
    address via ares_set_sortlist(). However, users may externally use ares_inet_net_pton() for other purposes
    and thus be vulnerable to more severe issues. This issue has been fixed in 1.19.1. (CVE-2023-31130)

  - c-ares is an asynchronous resolver library. When /dev/urandom or RtlGenRandom() are unavailable, c-ares
    uses rand() to generate random numbers used for DNS query ids. This is not a CSPRNG, and it is also not
    seeded by srand() so will generate predictable output. Input from the random number generator is fed into
    a non-compilant RC4 implementation and may not be as strong as the original RC4 implementation. No attempt
    is made to look for modern OS-provided CSPRNGs like arc4random() that is widely available. This issue has
    been fixed in version 1.19.1. (CVE-2023-31147)

  - c-ares is an asynchronous resolver library. c-ares is vulnerable to denial of service. If a target
    resolver sends a query, the attacker forges a malformed UDP packet with a length of 0 and returns them to
    the target resolver. The target resolver erroneously interprets the 0 length as a graceful shutdown of the
    connection. This issue has been patched in version 1.19.1. (CVE-2023-32067)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2023:3577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2209494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2209497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2209501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2209502");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-31147");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs-full-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs-nodemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs-packaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:nodejs-packaging-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:npm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:9");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 9.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'nodejs-18.14.2-3.module+el9.2.0+14843+acebbfea', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-18.14.2-3.module+el9.2.0+14843+acebbfea', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-18.14.2-3.module+el9.2.0+14843+acebbfea', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-debuginfo-18.14.2-3.module+el9.2.0+14843+acebbfea', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-debuginfo-18.14.2-3.module+el9.2.0+14843+acebbfea', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-debuginfo-18.14.2-3.module+el9.2.0+14843+acebbfea', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-debugsource-18.14.2-3.module+el9.2.0+14843+acebbfea', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-debugsource-18.14.2-3.module+el9.2.0+14843+acebbfea', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-debugsource-18.14.2-3.module+el9.2.0+14843+acebbfea', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-devel-18.14.2-3.module+el9.2.0+14843+acebbfea', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-devel-18.14.2-3.module+el9.2.0+14843+acebbfea', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-devel-18.14.2-3.module+el9.2.0+14843+acebbfea', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-docs-18.14.2-3.module+el9.2.0+14843+acebbfea', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-full-i18n-18.14.2-3.module+el9.2.0+14843+acebbfea', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-full-i18n-18.14.2-3.module+el9.2.0+14843+acebbfea', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-full-i18n-18.14.2-3.module+el9.2.0+14843+acebbfea', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs-nodemon-2.0.20-2.module+el9.2.0+14843+acebbfea', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-packaging-2021.06-4.module+el9.2.0+14843+acebbfea', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs-packaging-bundler-2021.06-4.module+el9.2.0+14843+acebbfea', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'npm-9.5.0-1.18.14.2.3.module+el9.2.0+14843+acebbfea', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'npm-9.5.0-1.18.14.2.3.module+el9.2.0+14843+acebbfea', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'npm-9.5.0-1.18.14.2.3.module+el9.2.0+14843+acebbfea', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs / nodejs-debuginfo / nodejs-debugsource / nodejs-devel / etc');
}

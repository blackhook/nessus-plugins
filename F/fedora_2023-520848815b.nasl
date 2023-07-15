#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-520848815b
#

include('compat.inc');

if (description)
{
  script_id(176408);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/05");

  script_cve_id(
    "CVE-2023-31124",
    "CVE-2023-31130",
    "CVE-2023-31147",
    "CVE-2023-32067"
  );
  script_xref(name:"FEDORA", value:"2023-520848815b");

  script_name(english:"Fedora 38 : c-ares (2023-520848815b)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 38 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2023-520848815b advisory.

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
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-520848815b");
  script_set_attribute(attribute:"solution", value:
"Update the affected c-ares package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-31147");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:c-ares");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^38([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 38', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'c-ares-1.19.1-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'c-ares');
}

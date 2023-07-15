#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2022:8062.
##

include('compat.inc');

if (description)
{
  script_id(167953);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/24");

  script_cve_id("CVE-2022-30698", "CVE-2022-30699");
  script_xref(name:"ALSA", value:"2022:8062");

  script_name(english:"AlmaLinux 9 : unbound (ALSA-2022:8062)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2022:8062 advisory.

  - NLnet Labs Unbound, up to and including version 1.16.1 is vulnerable to a novel type of the ghost domain
    names attack. The vulnerability works by targeting an Unbound instance. Unbound is queried for a
    subdomain of a rogue domain name. The rogue nameserver returns delegation information for the subdomain
    that updates Unbound's delegation cache. This action can be repeated before expiry of the delegation
    information by querying Unbound for a second level subdomain which the rogue nameserver provides new
    delegation information. Since Unbound is a child-centric resolver, the ever-updating child delegation
    information can keep a rogue domain name resolvable long after revocation. From version 1.16.2 on, Unbound
    checks the validity of parent delegation records before using cached delegation information.
    (CVE-2022-30698)

  - NLnet Labs Unbound, up to and including version 1.16.1, is vulnerable to a novel type of the ghost domain
    names attack. The vulnerability works by targeting an Unbound instance. Unbound is queried for a rogue
    domain name when the cached delegation information is about to expire. The rogue nameserver delays the
    response so that the cached delegation information is expired. Upon receiving the delayed answer
    containing the delegation information, Unbound overwrites the now expired entries. This action can be
    repeated when the delegation information is about to expire making the rogue delegation information ever-
    updating. From version 1.16.2 on, Unbound stores the start time for a query and uses that to decide if the
    cached delegation information can be overwritten. (CVE-2022-30699)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2022-8062.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30699");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(613);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:unbound-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:unbound-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::crb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 9.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'python3-unbound-1.16.2-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-1.16.2-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-devel-1.16.2-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unbound-libs-1.16.2-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python3-unbound / unbound / unbound-devel / unbound-libs');
}

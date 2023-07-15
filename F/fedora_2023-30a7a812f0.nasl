#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-30a7a812f0
#

include('compat.inc');

if (description)
{
  script_id(170691);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/27");

  script_cve_id(
    "CVE-2021-44854",
    "CVE-2021-44855",
    "CVE-2021-44856",
    "CVE-2022-41765",
    "CVE-2022-41767",
    "CVE-2022-47927",
    "CVE-2023-22909",
    "CVE-2023-22911",
    "CVE-2023-22945"
  );
  script_xref(name:"FEDORA", value:"2023-30a7a812f0");

  script_name(english:"Fedora 37 : mediawiki (2023-30a7a812f0)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 37 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2023-30a7a812f0 advisory.

  - An issue was discovered in MediaWiki before 1.35.5, 1.36.x before 1.36.3, and 1.37.x before 1.37.1. The
    REST API publicly caches results from private wikis. (CVE-2021-44854)

  - An issue was discovered in MediaWiki before 1.35.5, 1.36.x before 1.36.3, and 1.37.x before 1.37.1. There
    is Blind Stored XSS via a URL to the Upload Image feature. (CVE-2021-44855)

  - An issue was discovered in MediaWiki before 1.35.5, 1.36.x before 1.36.3, and 1.37.x before 1.37.1. A
    title blocked by AbuseFilter can be created via Special:ChangeContentModel due to the mishandling of the
    EditFilterMergedContent hook return value. (CVE-2021-44856)

  - An issue was discovered in MediaWiki before 1.35.8, 1.36.x and 1.37.x before 1.37.5, and 1.38.x before
    1.38.3. HTMLUserTextField exposes the existence of hidden users. (CVE-2022-41765)

  - An issue was discovered in MediaWiki before 1.35.8, 1.36.x and 1.37.x before 1.37.5, and 1.38.x before
    1.38.3. When changes made by an IP address are reassigned to a user (using reassignEdits.php), the changes
    will still be attributed to the IP address on Special:Contributions when doing a range lookup.
    (CVE-2022-41767)

  - An issue was discovered in MediaWiki before 1.35.9, 1.36.x through 1.38.x before 1.38.5, and 1.39.x before
    1.39.1. When installing with a pre-existing data directory that has weak permissions, the SQLite files are
    created with file mode 0644, i.e., world readable to local users. These files include credentials data.
    (CVE-2022-47927)

  - An issue was discovered in MediaWiki before 1.35.9, 1.36.x through 1.38.x before 1.38.5, and 1.39.x before
    1.39.1. SpecialMobileHistory allows remote attackers to cause a denial of service because database queries
    are slow. (CVE-2023-22909)

  - An issue was discovered in MediaWiki before 1.35.9, 1.36.x through 1.38.x before 1.38.5, and 1.39.x before
    1.39.1. E-Widgets does widget replacement in HTML attributes, which can lead to XSS, because widget
    authors often do not expect that their widget is executed in an HTML attribute context. (CVE-2023-22911)

  - In the GrowthExperiments extension for MediaWiki through 1.39, the growthmanagementorlist API allows
    blocked users (blocked in ApiManageMentorList) to enroll as mentors or edit any of their mentorship-
    related properties. (CVE-2023-22945)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-30a7a812f0");
  script_set_attribute(attribute:"solution", value:
"Update the affected mediawiki package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22911");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mediawiki");
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
if (! preg(pattern:"^37([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 37', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'mediawiki-1.38.5-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mediawiki');
}

#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1310-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153669);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/07");

  script_cve_id(
    "CVE-2021-30606",
    "CVE-2021-30607",
    "CVE-2021-30608",
    "CVE-2021-30609",
    "CVE-2021-30610",
    "CVE-2021-30611",
    "CVE-2021-30612",
    "CVE-2021-30613",
    "CVE-2021-30614",
    "CVE-2021-30615",
    "CVE-2021-30616",
    "CVE-2021-30617",
    "CVE-2021-30618",
    "CVE-2021-30619",
    "CVE-2021-30620",
    "CVE-2021-30621",
    "CVE-2021-30622",
    "CVE-2021-30623",
    "CVE-2021-30624"
  );
  script_xref(name:"IAVA", value:"2021-A-0401-S");

  script_name(english:"openSUSE 15 Security Update : opera (openSUSE-SU-2021:1310-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has a package installed that is affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1310-1 advisory.

  - Chromium: CVE-2021-30606 Use after free in Blink (CVE-2021-30606)

  - Chromium: CVE-2021-30607 Use after free in Permissions (CVE-2021-30607)

  - Chromium: CVE-2021-30608 Use after free in Web Share (CVE-2021-30608)

  - Chromium: CVE-2021-30609 Use after free in Sign-In (CVE-2021-30609)

  - Chromium: CVE-2021-30610 Use after free in Extensions API (CVE-2021-30610)

  - Chromium: CVE-2021-30611 Use after free in WebRTC (CVE-2021-30611)

  - Chromium: CVE-2021-30612 Use after free in WebRTC (CVE-2021-30612)

  - Chromium: CVE-2021-30613 Use after free in Base internals (CVE-2021-30613)

  - Chromium: CVE-2021-30614 Heap buffer overflow in TabStrip (CVE-2021-30614)

  - Chromium: CVE-2021-30615 Cross-origin data leak in Navigation (CVE-2021-30615)

  - Chromium: CVE-2021-30616 Use after free in Media (CVE-2021-30616)

  - Chromium: CVE-2021-30617 Policy bypass in Blink (CVE-2021-30617)

  - Chromium: CVE-2021-30618 Inappropriate implementation in DevTools (CVE-2021-30618)

  - Chromium: CVE-2021-30619 UI Spoofing in Autofill (CVE-2021-30619)

  - Chromium: CVE-2021-30620 Insufficient policy enforcement in Blink (CVE-2021-30620)

  - Chromium: CVE-2021-30621 UI Spoofing in Autofill (CVE-2021-30621)

  - Chromium: CVE-2021-30622 Use after free in WebApp Installs (CVE-2021-30622)

  - Chromium: CVE-2021-30623 Use after free in Bookmarks (CVE-2021-30623)

  - Chromium: CVE-2021-30624 Use after free in Autofill (CVE-2021-30624)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZDRKVDFEPABXRR653626WGJRZWK5HZ7Y/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0265fbbf");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30606");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30607");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30608");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30609");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30610");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30611");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30612");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30613");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30614");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30615");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30616");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30617");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30618");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30619");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30620");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30621");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30622");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30623");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30624");
  script_set_attribute(attribute:"solution", value:
"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30624");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.2', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'opera-79.0.4143.22-lp152.2.64.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'opera');
}

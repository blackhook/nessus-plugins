#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:10119-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(164951);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/30");

  script_cve_id(
    "CVE-2022-3038",
    "CVE-2022-3039",
    "CVE-2022-3040",
    "CVE-2022-3041",
    "CVE-2022-3042",
    "CVE-2022-3043",
    "CVE-2022-3044",
    "CVE-2022-3045",
    "CVE-2022-3046",
    "CVE-2022-3047",
    "CVE-2022-3048",
    "CVE-2022-3049",
    "CVE-2022-3050",
    "CVE-2022-3051",
    "CVE-2022-3052",
    "CVE-2022-3053",
    "CVE-2022-3054",
    "CVE-2022-3055",
    "CVE-2022-3056",
    "CVE-2022-3057",
    "CVE-2022-3058",
    "CVE-2022-3071",
    "CVE-2022-3075"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/29");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/20");

  script_name(english:"openSUSE 15 Security Update : chromium (openSUSE-SU-2022:10119-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:10119-1 advisory.

  - Use after free in Network Service. (CVE-2022-3038)

  - Use after free in WebSQL. (CVE-2022-3039, CVE-2022-3041)

  - Use after free in Layout. (CVE-2022-3040)

  - Use after free in PhoneHub. (CVE-2022-3042)

  - Heap buffer overflow in Screen Capture. (CVE-2022-3043)

  - Inappropriate implementation in Site Isolation. (CVE-2022-3044)

  - Insufficient validation of untrusted input in V8. (CVE-2022-3045)

  - Use after free in Browser Tag. (CVE-2022-3046)

  - Insufficient policy enforcement in Extensions API. (CVE-2022-3047)

  - Inappropriate implementation in Chrome OS lockscreen. (CVE-2022-3048)

  - Use after free in SplitScreen. (CVE-2022-3049)

  - Heap buffer overflow in WebUI. (CVE-2022-3050)

  - Heap buffer overflow in Exosphere. (CVE-2022-3051)

  - Heap buffer overflow in Window Manager. (CVE-2022-3052)

  - Inappropriate implementation in Pointer Lock. (CVE-2022-3053)

  - Insufficient policy enforcement in DevTools. (CVE-2022-3054)

  - Use after free in Passwords. (CVE-2022-3055)

  - Insufficient policy enforcement in Content Security Policy. (CVE-2022-3056)

  - Inappropriate implementation in iframe Sandbox. (CVE-2022-3057)

  - Use after free in Sign-In Flow. (CVE-2022-3058)

  - Use after free in Tab Strip. (CVE-2022-3071)

  - Insufficient data validation in Mojo. (CVE-2022-3075)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202403");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203102");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GAVZ7A2NRXHLI7C5TFF7GQHYKEGQIQRR/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?492af222");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3038");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3039");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3040");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3041");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3042");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3043");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3044");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3045");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3046");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3047");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3048");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3049");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3050");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3051");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3052");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3053");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3054");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3055");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3056");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3057");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3058");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3071");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3075");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromedriver and / or chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3071");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3075");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.4");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.4)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.4', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'chromedriver-105.0.5195.102-bp154.2.26.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-105.0.5195.102-bp154.2.26.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-105.0.5195.102-bp154.2.26.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-105.0.5195.102-bp154.2.26.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromedriver / chromium');
}

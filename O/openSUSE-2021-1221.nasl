#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1221-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153000);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/20");

  script_cve_id(
    "CVE-2021-30598",
    "CVE-2021-30599",
    "CVE-2021-30600",
    "CVE-2021-30601",
    "CVE-2021-30602",
    "CVE-2021-30603",
    "CVE-2021-30604"
  );
  script_xref(name:"IAVA", value:"2021-A-0385-S");

  script_name(english:"openSUSE 15 Security Update : opera (openSUSE-SU-2021:1221-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has a package installed that is affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1221-1 advisory.

  - Type confusion in V8 in Google Chrome prior to 92.0.4515.159 allowed a remote attacker to execute
    arbitrary code inside a sandbox via a crafted HTML page. (CVE-2021-30598, CVE-2021-30599)

  - Use after free in Printing in Google Chrome prior to 92.0.4515.159 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-30600)

  - Use after free in Extensions API in Google Chrome prior to 92.0.4515.159 allowed an attacker who convinced
    a user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-30601)

  - Use after free in WebRTC in Google Chrome prior to 92.0.4515.159 allowed an attacker who convinced a user
    to visit a malicious website to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-30602)

  - Data race in WebAudio in Google Chrome prior to 92.0.4515.159 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-30603)

  - Use after free in ANGLE in Google Chrome prior to 92.0.4515.159 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-30604)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/AONJYVX4FYNEW6Z2RBON633JUD667L7M/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35ae9e03");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30598");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30599");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30600");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30601");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30602");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30603");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30604");
  script_set_attribute(attribute:"solution", value:
"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30604");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'opera-78.0.4093.184-lp152.2.61.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE}
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
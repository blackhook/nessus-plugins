#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:10254-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(169444);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/01");

  script_cve_id(
    "CVE-2022-4262",
    "CVE-2022-4436",
    "CVE-2022-4437",
    "CVE-2022-4438",
    "CVE-2022-4439",
    "CVE-2022-4440"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/12/26");

  script_name(english:"openSUSE 15 Security Update : opera (openSUSE-SU-2022:10254-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has a package installed that is affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:10254-1 advisory.

  - Type confusion in V8 in Google Chrome prior to 108.0.5359.94 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2022-4262)

  - Use after free in Blink Media in Google Chrome prior to 108.0.5359.124 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2022-4436)

  - Use after free in Mojo IPC in Google Chrome prior to 108.0.5359.124 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2022-4437)

  - Use after free in Blink Frames in Google Chrome prior to 108.0.5359.124 allowed a remote attacker who
    convinced the user to engage in specific UI interactions to potentially exploit heap corruption via a
    crafted HTML page. (Chromium security severity: High) (CVE-2022-4438)

  - Use after free in Aura in Google Chrome on Windows prior to 108.0.5359.124 allowed a remote attacker who
    convinced the user to engage in specific UI interactions to potentially exploit heap corruption via
    specific UI interactions. (Chromium security severity: High) (CVE-2022-4439)

  - Use after free in Profiles in Google Chrome prior to 108.0.5359.124 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2022-4440)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EM2NIV5V5735TOCNGG6AUH4KJ62D3DNR/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0f277a9");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4262");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4436");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4437");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4438");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4439");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4440");
  script_set_attribute(attribute:"solution", value:
"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4440");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.4)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.4', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'opera-94.0.4606.38-lp154.2.35.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'opera');
}

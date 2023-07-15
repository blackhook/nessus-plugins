#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:10221-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(168241);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/08");

  script_cve_id("CVE-2022-4135");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/12/19");
  script_xref(name:"IAVA", value:"2022-A-0501-S");

  script_name(english:"openSUSE 15 Security Update : chromium (openSUSE-SU-2022:10221-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by a vulnerability as referenced in the
openSUSE-SU-2022:10221-1 advisory.

  - Heap buffer overflow in GPU in Google Chrome prior to 107.0.5304.121 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (Chromium security severity: High) (CVE-2022-4135)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205736");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/I37Q3H73QY7ILHFMPWD4NEERBM5GWYLD/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4aa6575f");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4135");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromedriver and / or chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4135");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.4");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_release !~ "^(SUSE15\.3|SUSE15\.4)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3 / 15.4', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'chromedriver-107.0.5304.121-bp154.2.46.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-107.0.5304.121-bp154.2.46.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-107.0.5304.121-bp154.2.46.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-107.0.5304.121-bp154.2.46.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-107.0.5304.121-bp154.2.46.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-107.0.5304.121-bp154.2.46.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-107.0.5304.121-bp154.2.46.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-107.0.5304.121-bp154.2.46.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
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

#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1254-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153394);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/15");

  script_cve_id("CVE-2021-30475");

  script_name(english:"openSUSE 15 Security Update : libaom (openSUSE-SU-2021:1254-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by a vulnerability as referenced in the
openSUSE-SU-2021:1254-1 advisory.

  - aom_dsp/noise_model.c in libaom in AOMedia before 2021-03-24 has a buffer overflow. (CVE-2021-30475)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189497");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/X2RSNQSM4KBVYVR4O53XXM7IY2AXF6OC/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a903cb89");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-30475");
  script_set_attribute(attribute:"solution", value:
"Update the affected aom-tools, libaom-devel, libaom0 and / or libaom0-32bit packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30475");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:aom-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaom-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaom0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaom0-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
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
    {'reference':'aom-tools-1.0.0-lp152.3.3.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libaom-devel-1.0.0-lp152.3.3.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libaom0-1.0.0-lp152.3.3.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libaom0-32bit-1.0.0-lp152.3.3.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'aom-tools / libaom-devel / libaom0 / libaom0-32bit');
}

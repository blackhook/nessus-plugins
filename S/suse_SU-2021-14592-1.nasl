#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:14592-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150508);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/10");

  script_cve_id(
    "CVE-2020-3123",
    "CVE-2020-3327",
    "CVE-2020-3341",
    "CVE-2020-3350",
    "CVE-2020-3481"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:14592-1");

  script_name(english:"SUSE SLES11 Security Update : clamav (SUSE-SU-2021:14592-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has a package installed that is affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:14592-1 advisory.

  - A vulnerability in the Data-Loss-Prevention (DLP) module in Clam AntiVirus (ClamAV) Software versions
    0.102.1 and 0.102.0 could allow an unauthenticated, remote attacker to cause a denial of service condition
    on an affected device. The vulnerability is due to an out-of-bounds read affecting users that have enabled
    the optional DLP feature. An attacker could exploit this vulnerability by sending a crafted email file to
    an affected device. An exploit could allow the attacker to cause the ClamAV scanning process crash,
    resulting in a denial of service condition. (CVE-2020-3123)

  - A vulnerability in the ARJ archive parsing module in Clam AntiVirus (ClamAV) Software versions 0.102.2
    could allow an unauthenticated, remote attacker to cause a denial of service condition on an affected
    device. The vulnerability is due to a heap buffer overflow read. An attacker could exploit this
    vulnerability by sending a crafted ARJ file to an affected device. An exploit could allow the attacker to
    cause the ClamAV scanning process crash, resulting in a denial of service condition. (CVE-2020-3327)

  - A vulnerability in the PDF archive parsing module in Clam AntiVirus (ClamAV) Software versions 0.101 -
    0.102.2 could allow an unauthenticated, remote attacker to cause a denial of service condition on an
    affected device. The vulnerability is due to a stack buffer overflow read. An attacker could exploit this
    vulnerability by sending a crafted PDF file to an affected device. An exploit could allow the attacker to
    cause the ClamAV scanning process crash, resulting in a denial of service condition. (CVE-2020-3341)

  - A vulnerability in the endpoint software of Cisco AMP for Endpoints and Clam AntiVirus could allow an
    authenticated, local attacker to cause the running software to delete arbitrary files on the system. The
    vulnerability is due to a race condition that could occur when scanning malicious files. An attacker with
    local shell access could exploit this vulnerability by executing a script that could trigger the race
    condition. A successful exploit could allow the attacker to delete arbitrary files on the system that the
    attacker would not normally have privileges to delete, producing system instability or causing the
    endpoint software to stop working. (CVE-2020-3350)

  - A vulnerability in the EGG archive parsing module in Clam AntiVirus (ClamAV) Software versions 0.102.0 -
    0.102.3 could allow an unauthenticated, remote attacker to cause a denial of service condition on an
    affected device. The vulnerability is due to a null pointer dereference. An attacker could exploit this
    vulnerability by sending a crafted EGG file to an affected device. An exploit could allow the attacker to
    cause the ClamAV scanning process crash, resulting in a denial of service condition. (CVE-2020-3481)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1118459");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1171981");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174250");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174255");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-January/008156.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e62cf16");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-3123");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-3327");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-3341");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-3350");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-3481");
  script_set_attribute(attribute:"solution", value:
"Update the affected clamav package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3350");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
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
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES11', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);

pkgs = [
    {'reference':'clamav-0.103.0-0.20.32', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'clamav-0.103.0-0.20.32', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  exists_check = NULL;
  rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release && exists_check) {
    if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
  else if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'clamav');
}

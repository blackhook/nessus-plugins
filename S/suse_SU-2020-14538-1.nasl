#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2020:14538-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150580);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-16846", "CVE-2020-17490", "CVE-2020-25592");
  script_xref(name:"SuSE", value:"SUSE-SU-2020:14538-1");
  script_xref(name:"IAVA", value:"2020-A-0195-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0134");

  script_name(english:"SUSE SLES11 Security Update : SUSE Manager Client Tools (SUSE-SU-2020:14538-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2020:14538-1 advisory.

  - An issue was discovered in SaltStack Salt through 3002. Sending crafted web requests to the Salt API, with
    the SSH client enabled, can result in shell injection. (CVE-2020-16846)

  - The TLS module within SaltStack Salt through 3002 creates certificates with weak file permissions.
    (CVE-2020-17490)

  - In SaltStack Salt through 3002, salt-netapi improperly validates eauth credentials and tokens. A user can
    bypass authentication and invoke Salt SSH. (CVE-2020-25592)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167907");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1169664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178319");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178362");
  # https://lists.suse.com/pipermail/sle-security-updates/2020-November/007715.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7abbc279");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-16846");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-17490");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25592");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25592");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SaltStack Salt REST API Arbitrary Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:koan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mgr-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-spacewalk-check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-spacewalk-client-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-spacewalk-client-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-minion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacecmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-client-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:spacewalk-client-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES11" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);

pkgs = [
    {'reference':'koan-2.2.2-0.68.12', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'mgr-daemon-4.1.3-5.20', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-spacewalk-check-4.1.7-27.38', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-spacewalk-client-setup-4.1.7-27.38', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'python2-spacewalk-client-tools-4.1.7-27.38', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'salt-2016.11.10-43.63', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'salt-doc-2016.11.10-43.63', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'salt-minion-2016.11.10-43.63', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'spacecmd-4.1.8-18.72', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'spacewalk-check-4.1.7-27.38', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'spacewalk-client-setup-4.1.7-27.38', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'spacewalk-client-tools-4.1.7-27.38', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3'},
    {'reference':'koan-2.2.2-0.68.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'mgr-daemon-4.1.3-5.20', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-spacewalk-check-4.1.7-27.38', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-spacewalk-client-setup-4.1.7-27.38', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'python2-spacewalk-client-tools-4.1.7-27.38', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'salt-2016.11.10-43.63', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'salt-doc-2016.11.10-43.63', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'salt-minion-2016.11.10-43.63', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'spacecmd-4.1.8-18.72', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'spacewalk-check-4.1.7-27.38', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'spacewalk-client-setup-4.1.7-27.38', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'spacewalk-client-tools-4.1.7-27.38', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'koan-2.2.2-0.68.12', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'mgr-daemon-4.1.3-5.20', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-spacewalk-check-4.1.7-27.38', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-spacewalk-client-setup-4.1.7-27.38', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'python2-spacewalk-client-tools-4.1.7-27.38', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'salt-2016.11.10-43.63', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'salt-doc-2016.11.10-43.63', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'salt-minion-2016.11.10-43.63', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'spacecmd-4.1.8-18.72', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'spacewalk-check-4.1.7-27.38', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'spacewalk-client-setup-4.1.7-27.38', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'spacewalk-client-tools-4.1.7-27.38', 'sp':'3', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3'},
    {'reference':'koan-2.2.2-0.68.12', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'mgr-daemon-4.1.3-5.20', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-spacewalk-check-4.1.7-27.38', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-spacewalk-client-setup-4.1.7-27.38', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'python2-spacewalk-client-tools-4.1.7-27.38', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'salt-2016.11.10-43.63', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'salt-doc-2016.11.10-43.63', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'salt-minion-2016.11.10-43.63', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'spacecmd-4.1.8-18.72', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'spacewalk-check-4.1.7-27.38', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'spacewalk-client-setup-4.1.7-27.38', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'spacewalk-client-tools-4.1.7-27.38', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
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
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'koan / mgr-daemon / python2-spacewalk-check / etc');
}

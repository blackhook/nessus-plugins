#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:4082-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(167936);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2018-20846",
    "CVE-2018-21010",
    "CVE-2020-27824",
    "CVE-2020-27842",
    "CVE-2020-27843",
    "CVE-2020-27845"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:4082-1");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : openjpeg (SUSE-SU-2022:4082-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2022:4082-1 advisory.

  - Out-of-bounds accesses in the functions pi_next_lrcp, pi_next_rlcp, pi_next_rpcl, pi_next_pcrl,
    pi_next_rpcl, and pi_next_cprl in openmj2/pi.c in OpenJPEG through 2.3.0 allow remote attackers to cause a
    denial of service (application crash). (CVE-2018-20846)

  - OpenJPEG before 2.3.1 has a heap buffer overflow in color_apply_icc_profile in bin/common/color.c.
    (CVE-2018-21010)

  - A flaw was found in OpenJPEG's encoder in the opj_dwt_calc_explicit_stepsizes() function. This flaw allows
    an attacker who can supply crafted input to decomposition levels to cause a buffer overflow. The highest
    threat from this vulnerability is to system availability. (CVE-2020-27824)

  - There's a flaw in openjpeg's t2 encoder in versions prior to 2.4.0. An attacker who is able to provide
    crafted input to be processed by openjpeg could cause a null pointer dereference. The highest impact of
    this flaw is to application availability. (CVE-2020-27842)

  - A flaw was found in OpenJPEG in versions prior to 2.4.0. This flaw allows an attacker to provide specially
    crafted input to the conversion or encoding functionality, causing an out-of-bounds read. The highest
    threat from this vulnerability is system availability. (CVE-2020-27843)

  - There's a flaw in src/lib/openjp2/pi.c of openjpeg in versions prior to 2.4.0. If an attacker is able to
    provide untrusted input to openjpeg's conversion/encoding functionality, they could cause an out-of-bounds
    read. The highest impact of this flaw is to application availability. (CVE-2020-27845)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1140205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1149789");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179821");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180043");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180046");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-November/012995.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b8a07bf");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20846");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-21010");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27824");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27842");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27843");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27845");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-21010");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenjpeg1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenjpeg1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openjpeg-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.3|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP3/4", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1|2|3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP0/1/2/3/4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libopenjpeg1-1.5.2-150000.4.10.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1']},
    {'reference':'libopenjpeg1-32bit-1.5.2-150000.4.10.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1']},
    {'reference':'openjpeg-devel-1.5.2-150000.4.10.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1']},
    {'reference':'libopenjpeg1-1.5.2-150000.4.10.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'openjpeg-devel-1.5.2-150000.4.10.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'libopenjpeg1-1.5.2-150000.4.10.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libopenjpeg1-32bit-1.5.2-150000.4.10.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15']},
    {'reference':'openjpeg-devel-1.5.2-150000.4.10.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libopenjpeg1-1.5.2-150000.4.10.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libopenjpeg1-1.5.2-150000.4.10.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'openjpeg-devel-1.5.2-150000.4.10.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'openjpeg-devel-1.5.2-150000.4.10.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libopenjpeg1-1.5.2-150000.4.10.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libopenjpeg1-1.5.2-150000.4.10.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'openjpeg-devel-1.5.2-150000.4.10.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'openjpeg-devel-1.5.2-150000.4.10.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libopenjpeg1-1.5.2-150000.4.10.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libopenjpeg1-1.5.2-150000.4.10.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libopenjpeg1-1.5.2-150000.4.10.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'openjpeg-devel-1.5.2-150000.4.10.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'openjpeg-devel-1.5.2-150000.4.10.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'openjpeg-devel-1.5.2-150000.4.10.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libopenjpeg1-1.5.2-150000.4.10.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'openjpeg-devel-1.5.2-150000.4.10.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'libopenjpeg1-1.5.2-150000.4.10.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libopenjpeg1-1.5.2-150000.4.10.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'openjpeg-devel-1.5.2-150000.4.10.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'openjpeg-devel-1.5.2-150000.4.10.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libopenjpeg1-1.5.2-150000.4.10.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libopenjpeg1-32bit-1.5.2-150000.4.10.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'openjpeg-1.5.2-150000.4.10.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'openjpeg-devel-1.5.2-150000.4.10.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'openjpeg-devel-32bit-1.5.2-150000.4.10.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libopenjpeg1-1.5.2-150000.4.10.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libopenjpeg1-32bit-1.5.2-150000.4.10.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'openjpeg-1.5.2-150000.4.10.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'openjpeg-devel-1.5.2-150000.4.10.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'openjpeg-devel-32bit-1.5.2-150000.4.10.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libopenjpeg1-1.5.2-150000.4.10.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15']},
    {'reference':'libopenjpeg1-32bit-1.5.2-150000.4.10.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15']},
    {'reference':'openjpeg-devel-1.5.2-150000.4.10.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libopenjpeg1 / libopenjpeg1-32bit / openjpeg / openjpeg-devel / etc');
}

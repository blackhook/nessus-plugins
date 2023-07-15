#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:2142-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(175541);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/13");

  script_cve_id(
    "CVE-2023-26551",
    "CVE-2023-26552",
    "CVE-2023-26553",
    "CVE-2023-26554"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:2142-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : ntp (SUSE-SU-2023:2142-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2023:2142-1 advisory.

  - mstolfp in libntp/mstolfp.c in NTP 4.2.8p15 has an out-of-bounds write in the cp<cpdec while loop. An
    adversary may be able to attack a client ntpq process, but cannot attack ntpd. (CVE-2023-26551)

  - mstolfp in libntp/mstolfp.c in NTP 4.2.8p15 has an out-of-bounds write when adding a decimal point. An
    adversary may be able to attack a client ntpq process, but cannot attack ntpd. (CVE-2023-26552)

  - mstolfp in libntp/mstolfp.c in NTP 4.2.8p15 has an out-of-bounds write when copying the trailing number.
    An adversary may be able to attack a client ntpq process, but cannot attack ntpd. (CVE-2023-26553)

  - mstolfp in libntp/mstolfp.c in NTP 4.2.8p15 has an out-of-bounds write when adding a '\0' character. An
    adversary may be able to attack a client ntpq process, but cannot attack ntpd. (CVE-2023-26554)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210387");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210388");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210389");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-May/029305.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-26551");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-26552");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-26553");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-26554");
  script_set_attribute(attribute:"solution", value:
"Update the affected ntp and / or ntp-doc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-26554");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'ntp-4.2.8p15-150000.4.22.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-legacy-release-15.4', 'sles-release-15.4']},
    {'reference':'ntp-4.2.8p15-150000.4.22.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ntp-doc-4.2.8p15-150000.4.22.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']}
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
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ntp / ntp-doc');
}

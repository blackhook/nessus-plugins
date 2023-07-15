##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:1869-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(161647);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id("CVE-2022-1552");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:1869-1");
  script_xref(name:"IAVB", value:"2022-B-0015-S");

  script_name(english:"SUSE SLES12 Security Update : postgresql12 (SUSE-SU-2022:1869-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by a vulnerability as referenced in the SUSE-
SU-2022:1869-1 advisory.

  - A flaw was found in PostgreSQL. There is an issue with incomplete efforts to operate safely when a
    privileged user is maintaining another user's objects. The Autovacuum, REINDEX, CREATE INDEX, REFRESH
    MATERIALIZED VIEW, CLUSTER, and pg_amcheck commands activated relevant protections too late or not at all
    during the process. This flaw allows an attacker with permission to create non-temporary objects in at
    least one schema to execute arbitrary SQL functions under a superuser identity. (CVE-2022-1552)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199475");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-May/011170.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90dd9dcb");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1552");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1552");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-server-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'postgresql12-12.11-3.27.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'postgresql12-contrib-12.11-3.27.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'postgresql12-devel-12.11-3.27.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'postgresql12-docs-12.11-3.27.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'postgresql12-plperl-12.11-3.27.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'postgresql12-plpython-12.11-3.27.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'postgresql12-pltcl-12.11-3.27.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'postgresql12-server-12.11-3.27.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sles-release-12.5']},
    {'reference':'postgresql12-server-devel-12.11-3.27.3', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'postgresql12 / postgresql12-contrib / postgresql12-devel / etc');
}

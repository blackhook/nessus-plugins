#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:0731-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159148);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2021-46657",
    "CVE-2021-46658",
    "CVE-2021-46659",
    "CVE-2021-46661",
    "CVE-2021-46663",
    "CVE-2021-46664",
    "CVE-2021-46665",
    "CVE-2021-46668",
    "CVE-2022-24048",
    "CVE-2022-24050",
    "CVE-2022-24051",
    "CVE-2022-24052"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:0731-1");

  script_name(english:"SUSE SLES15 Security Update : mariadb (SUSE-SU-2022:0731-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:0731-1 advisory.

  - get_sort_by_table in MariaDB before 10.6.2 allows an application crash via certain subquery uses of ORDER
    BY. (CVE-2021-46657)

  - save_window_function_values in MariaDB before 10.6.3 allows an application crash because of incorrect
    handling of with_window_func=true for a subquery. (CVE-2021-46658)

  - MariaDB before 10.7.2 allows an application crash because it does not recognize that
    SELECT_LEX::nest_level is local to each VIEW. (CVE-2021-46659)

  - MariaDB through 10.5.9 allows an application crash in find_field_in_tables and find_order_in_list via an
    unused common table expression (CTE). (CVE-2021-46661)

  - MariaDB through 10.5.13 allows a ha_maria::extra application crash via certain SELECT statements.
    (CVE-2021-46663)

  - MariaDB through 10.5.9 allows an application crash in sub_select_postjoin_aggr for a NULL value of aggr.
    (CVE-2021-46664)

  - MariaDB through 10.5.9 allows a sql_parse.cc application crash because of incorrect used_tables
    expectations. (CVE-2021-46665)

  - MariaDB through 10.5.9 allows an application crash via certain long SELECT DISTINCT statements that
    improperly interact with storage-engine resource limitations for temporary data structures.
    (CVE-2021-46668)

  - MariaDB CONNECT Storage Engine Stack-based Buffer Overflow Privilege Escalation Vulnerability. This
    vulnerability allows local attackers to escalate privileges on affected installations of MariaDB.
    Authentication is required to exploit this vulnerability. The specific flaw exists within the processing
    of SQL queries. The issue results from the lack of proper validation of the length of user-supplied data
    prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this vulnerability to
    escalate privileges and execute arbitrary code in the context of the service account. Was ZDI-CAN-16191.
    (CVE-2022-24048)

  - MariaDB CONNECT Storage Engine Use-After-Free Privilege Escalation Vulnerability. This vulnerability
    allows local attackers to escalate privileges on affected installations of MariaDB. Authentication is
    required to exploit this vulnerability. The specific flaw exists within the processing of SQL queries. The
    issue results from the lack of validating the existence of an object prior to performing operations on the
    object. An attacker can leverage this vulnerability to escalate privileges and execute arbitrary code in
    the context of the service account. Was ZDI-CAN-16207. (CVE-2022-24050)

  - MariaDB CONNECT Storage Engine Format String Privilege Escalation Vulnerability. This vulnerability allows
    local attackers to escalate privileges on affected installations of MariaDB. Authentication is required to
    exploit this vulnerability. The specific flaw exists within the processing of SQL queries. The issue
    results from the lack of proper validation of a user-supplied string before using it as a format
    specifier. An attacker can leverage this vulnerability to escalate privileges and execute arbitrary code
    in the context of the service account. Was ZDI-CAN-16193. (CVE-2022-24051)

  - MariaDB CONNECT Storage Engine Heap-based Buffer Overflow Privilege Escalation Vulnerability. This
    vulnerability allows local attackers to escalate privileges on affected installations of MariaDB.
    Authentication is required to exploit this vulnerability. The specific flaw exists within the processing
    of SQL queries. The issue results from the lack of proper validation of the length of user-supplied data
    prior to copying it to a fixed-length heap-based buffer. An attacker can leverage this vulnerability to
    escalate privileges and execute arbitrary code in the context of the service account. Was ZDI-CAN-16190.
    (CVE-2022-24052)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195325");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195334");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195339");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196016");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-March/010369.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78ef81e8");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46657");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46658");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46659");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46661");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46664");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46665");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46668");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-24048");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-24050");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-24051");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-24052");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24052");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmariadbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmariadbd19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-errormessages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libmariadbd-devel-10.5.15-150300.3.15.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'libmariadbd19-10.5.15-150300.3.15.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'mariadb-10.5.15-150300.3.15.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'mariadb-client-10.5.15-150300.3.15.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'mariadb-errormessages-10.5.15-150300.3.15.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']},
    {'reference':'mariadb-tools-10.5.15-150300.3.15.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-server-applications-release-15.3', 'sles-release-15.3']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libmariadbd-devel / libmariadbd19 / mariadb / mariadb-client / etc');
}

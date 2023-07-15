#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:2320-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151748);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id(
    "CVE-2015-3414",
    "CVE-2015-3415",
    "CVE-2019-19244",
    "CVE-2019-19317",
    "CVE-2019-19603",
    "CVE-2019-19645",
    "CVE-2019-19646",
    "CVE-2019-19880",
    "CVE-2019-19923",
    "CVE-2019-19924",
    "CVE-2019-19925",
    "CVE-2019-19926",
    "CVE-2019-19959",
    "CVE-2019-20218",
    "CVE-2020-9327",
    "CVE-2020-13434",
    "CVE-2020-13435",
    "CVE-2020-13630",
    "CVE-2020-13631",
    "CVE-2020-13632",
    "CVE-2020-15358"
  );
  script_xref(name:"IAVA", value:"2020-A-0358-S");

  script_name(english:"openSUSE 15 Security Update : sqlite3 (openSUSE-SU-2021:2320-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:2320-1 advisory.

  - SQLite before 3.8.9 does not properly implement the dequoting of collation-sequence names, which allows
    context-dependent attackers to cause a denial of service (uninitialized memory access and application
    crash) or possibly have unspecified other impact via a crafted COLLATE clause, as demonstrated by
    COLLATE at the end of a SELECT statement. (CVE-2015-3414)

  - The sqlite3VdbeExec function in vdbe.c in SQLite before 3.8.9 does not properly implement comparison
    operators, which allows context-dependent attackers to cause a denial of service (invalid free operation)
    or possibly have unspecified other impact via a crafted CHECK clause, as demonstrated by CHECK(0&O;>O) in a
    CREATE TABLE statement. (CVE-2015-3415)

  - sqlite3Select in select.c in SQLite 3.30.1 allows a crash if a sub-select uses both DISTINCT and window
    functions, and also has certain ORDER BY usage. (CVE-2019-19244)

  - lookupName in resolve.c in SQLite 3.30.1 omits bits from the colUsed bitmask in the case of a generated
    column, which allows attackers to cause a denial of service or possibly have unspecified other impact.
    (CVE-2019-19317)

  - SQLite 3.30.1 mishandles certain SELECT statements with a nonexistent VIEW, leading to an application
    crash. (CVE-2019-19603)

  - alter.c in SQLite through 3.30.1 allows attackers to trigger infinite recursion via certain types of self-
    referential views in conjunction with ALTER TABLE statements. (CVE-2019-19645)

  - pragma.c in SQLite through 3.30.1 mishandles NOT NULL in an integrity_check PRAGMA command in certain
    cases of generated columns. (CVE-2019-19646)

  - exprListAppendList in window.c in SQLite 3.30.1 allows attackers to trigger an invalid pointer dereference
    because constant integer values in ORDER BY clauses of window definitions are mishandled. (CVE-2019-19880)

  - flattenSubquery in select.c in SQLite 3.30.1 mishandles certain uses of SELECT DISTINCT involving a LEFT
    JOIN in which the right-hand side is a view. This can cause a NULL pointer dereference (or incorrect
    results). (CVE-2019-19923)

  - SQLite 3.30.1 mishandles certain parser-tree rewriting, related to expr.c, vdbeaux.c, and window.c. This
    is caused by incorrect sqlite3WindowRewrite() error handling. (CVE-2019-19924)

  - zipfileUpdate in ext/misc/zipfile.c in SQLite 3.30.1 mishandles a NULL pathname during an update of a ZIP
    archive. (CVE-2019-19925)

  - multiSelect in select.c in SQLite 3.30.1 mishandles certain errors during parsing, as demonstrated by
    errors from sqlite3WindowRewrite() calls. NOTE: this vulnerability exists because of an incomplete fix for
    CVE-2019-19880. (CVE-2019-19926)

  - ext/misc/zipfile.c in SQLite 3.30.1 mishandles certain uses of INSERT INTO in situations involving
    embedded '\0' characters in filenames, leading to a memory-management error that can be detected by (for
    example) valgrind. (CVE-2019-19959)

  - selectExpander in select.c in SQLite 3.30.1 proceeds with WITH stack unwinding even after a parsing error.
    (CVE-2019-20218)

  - SQLite through 3.32.0 has an integer overflow in sqlite3_str_vappendf in printf.c. (CVE-2020-13434)

  - SQLite through 3.32.0 has a segmentation fault in sqlite3ExprCodeTarget in expr.c. (CVE-2020-13435)

  - ext/fts3/fts3.c in SQLite before 3.32.0 has a use-after-free in fts3EvalNextRow, related to the snippet
    feature. (CVE-2020-13630)

  - SQLite before 3.32.0 allows a virtual table to be renamed to the name of one of its shadow tables, related
    to alter.c and build.c. (CVE-2020-13631)

  - ext/fts3/fts3_snippet.c in SQLite before 3.32.0 has a NULL pointer dereference via a crafted matchinfo()
    query. (CVE-2020-13632)

  - In SQLite before 3.32.3, select.c mishandles query-flattener optimization, leading to a multiSelectOrderBy
    heap overflow because of misuse of transitive properties for constant propagation. (CVE-2020-15358)

  - In SQLite 3.31.1, isAuxiliaryVtabOperator allows attackers to trigger a NULL pointer dereference and
    segmentation fault because of generated column optimizations. (CVE-2020-9327)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/928700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/928701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157818");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1159491");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1159715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1159847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1159850");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1160309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1160438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1160439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1164719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172091");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172234");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172236");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172240");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173641");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JD4EZ74IZ57MKTDKDVIUAIG6VCAEKMD5/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?405d0bcc");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-3414");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-3415");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19244");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19317");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19603");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19645");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19646");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19880");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19926");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-20218");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13434");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13435");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13630");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13631");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13632");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15358");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-9327");
  script_set_attribute(attribute:"solution", value:
"Update the affected libsqlite3-0, libsqlite3-0-32bit, sqlite3 and / or sqlite3-devel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19646");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsqlite3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsqlite3-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sqlite3-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

pkgs = [
    {'reference':'libsqlite3-0-3.36.0-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsqlite3-0-32bit-3.36.0-3.12.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sqlite3-3.36.0-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sqlite3-devel-3.36.0-3.12.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  rpm_spec_vers_cmp = NULL;
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libsqlite3-0 / libsqlite3-0-32bit / sqlite3 / sqlite3-devel');
}

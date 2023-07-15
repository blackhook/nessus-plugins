##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0064. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147397);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/11");

  script_cve_id(
    "CVE-2019-5018",
    "CVE-2019-16168",
    "CVE-2019-20218",
    "CVE-2020-6405",
    "CVE-2020-9327",
    "CVE-2020-13630",
    "CVE-2020-13631",
    "CVE-2020-13632"
  );
  script_bugtraq_id(108294);

  script_name(english:"NewStart CGSL MAIN 6.02 : sqlite Multiple Vulnerabilities (NS-SA-2021-0064)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has sqlite packages installed that are affected by multiple
vulnerabilities:

  - An exploitable use after free vulnerability exists in the window function functionality of Sqlite3 3.26.0.
    A specially crafted SQL command can cause a use after free vulnerability, potentially resulting in remote
    code execution. An attacker can send a malicious SQL command to trigger this vulnerability.
    (CVE-2019-5018)

  - In SQLite through 3.29.0, whereLoopAddBtreeIndex in sqlite3.c can crash a browser or other application
    because of missing validation of a sqlite_stat1 sz field, aka a severe division by zero in the query
    planner. (CVE-2019-16168)

  - In SQLite 3.31.1, isAuxiliaryVtabOperator allows attackers to trigger a NULL pointer dereference and
    segmentation fault because of generated column optimizations. (CVE-2020-9327)

  - selectExpander in select.c in SQLite 3.30.1 proceeds with WITH stack unwinding even after a parsing error.
    (CVE-2019-20218)

  - ext/fts3/fts3.c in SQLite before 3.32.0 has a use-after-free in fts3EvalNextRow, related to the snippet
    feature. (CVE-2020-13630)

  - SQLite before 3.32.0 allows a virtual table to be renamed to the name of one of its shadow tables, related
    to alter.c and build.c. (CVE-2020-13631)

  - ext/fts3/fts3_snippet.c in SQLite before 3.32.0 has a NULL pointer dereference via a crafted matchinfo()
    query. (CVE-2020-13632)

  - Out of bounds read in SQLite in Google Chrome prior to 80.0.3987.87 allowed a remote attacker to obtain
    potentially sensitive information from process memory via a crafted HTML page. (CVE-2020-6405)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0064");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL sqlite packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5018");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL MAIN 6.02': [
    'lemon-3.26.0-11.el8',
    'lemon-debuginfo-3.26.0-11.el8',
    'sqlite-3.26.0-11.el8',
    'sqlite-analyzer-3.26.0-11.el8',
    'sqlite-analyzer-debuginfo-3.26.0-11.el8',
    'sqlite-debuginfo-3.26.0-11.el8',
    'sqlite-debugsource-3.26.0-11.el8',
    'sqlite-devel-3.26.0-11.el8',
    'sqlite-doc-3.26.0-11.el8',
    'sqlite-libs-3.26.0-11.el8',
    'sqlite-libs-debuginfo-3.26.0-11.el8',
    'sqlite-tcl-3.26.0-11.el8',
    'sqlite-tcl-debuginfo-3.26.0-11.el8'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'sqlite');
}

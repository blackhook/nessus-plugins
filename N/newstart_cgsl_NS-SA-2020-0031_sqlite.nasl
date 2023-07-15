#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0031. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138774);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2019-8457",
    "CVE-2019-13752",
    "CVE-2019-13753",
    "CVE-2019-19923",
    "CVE-2019-19924",
    "CVE-2019-19925",
    "CVE-2019-19959"
  );

  script_name(english:"NewStart CGSL MAIN 6.01 : sqlite Multiple Vulnerabilities (NS-SA-2020-0031)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.01, has sqlite packages installed that are affected by multiple
vulnerabilities:

  - SQLite3 from 3.6.0 to and including 3.27.2 is vulnerable
    to heap out-of-bound read in the rtreenode() function
    when handling invalid rtree tables. (CVE-2019-8457)

  - SQLite 3.30.1 mishandles certain parser-tree rewriting,
    related to expr.c, vdbeaux.c, and window.c. This is
    caused by incorrect sqlite3WindowRewrite() error
    handling. (CVE-2019-19924)

  - flattenSubquery in select.c in SQLite 3.30.1 mishandles
    certain uses of SELECT DISTINCT involving a LEFT JOIN in
    which the right-hand side is a view. This can cause a
    NULL pointer dereference (or incorrect results).
    (CVE-2019-19923)

  - Out of bounds read in SQLite in Google Chrome prior to
    79.0.3945.79 allowed a remote attacker to obtain
    potentially sensitive information from process memory
    via a crafted HTML page. (CVE-2019-13752,
    CVE-2019-13753)

  - zipfileUpdate in ext/misc/zipfile.c in SQLite 3.30.1
    mishandles a NULL pathname during an update of a ZIP
    archive. (CVE-2019-19925)

  - ext/misc/zipfile.c in SQLite 3.30.1 mishandles certain
    uses of INSERT INTO in situations involving embedded
    '\0' characters in filenames, leading to a memory-
    management error that can be detected by (for example)
    valgrind. (CVE-2019-19959)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0031");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL sqlite packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8457");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL MAIN 6.01")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.01');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 6.01": [
    "lemon-3.26.0-6.el8",
    "lemon-debuginfo-3.26.0-6.el8",
    "sqlite-3.26.0-6.el8",
    "sqlite-analyzer-3.26.0-6.el8",
    "sqlite-analyzer-debuginfo-3.26.0-6.el8",
    "sqlite-debuginfo-3.26.0-6.el8",
    "sqlite-debugsource-3.26.0-6.el8",
    "sqlite-devel-3.26.0-6.el8",
    "sqlite-doc-3.26.0-6.el8",
    "sqlite-libs-3.26.0-6.el8",
    "sqlite-libs-debuginfo-3.26.0-6.el8",
    "sqlite-tcl-3.26.0-6.el8",
    "sqlite-tcl-debuginfo-3.26.0-6.el8"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sqlite");
}

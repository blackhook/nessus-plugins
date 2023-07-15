##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0052. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160749);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2020-13434", "CVE-2020-15358");
  script_xref(name:"IAVA", value:"2020-A-0358-S");

  script_name(english:"NewStart CGSL MAIN 6.02 : sqlite Multiple Vulnerabilities (NS-SA-2022-0052)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has sqlite packages installed that are affected by multiple
vulnerabilities:

  - SQLite through 3.32.0 has an integer overflow in sqlite3_str_vappendf in printf.c. (CVE-2020-13434)

  - In SQLite before 3.32.3, select.c mishandles query-flattener optimization, leading to a multiSelectOrderBy
    heap overflow because of misuse of transitive properties for constant propagation. (CVE-2020-15358)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0052");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-13434");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-15358");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL sqlite packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15358");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:lemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:lemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sqlite-analyzer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sqlite-analyzer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sqlite-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sqlite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sqlite-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sqlite-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sqlite-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sqlite-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sqlite-tcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'lemon-3.26.0-13.el8',
    'lemon-debuginfo-3.26.0-13.el8',
    'sqlite-3.26.0-13.el8',
    'sqlite-analyzer-3.26.0-13.el8',
    'sqlite-analyzer-debuginfo-3.26.0-13.el8',
    'sqlite-debuginfo-3.26.0-13.el8',
    'sqlite-debugsource-3.26.0-13.el8',
    'sqlite-devel-3.26.0-13.el8',
    'sqlite-doc-3.26.0-13.el8',
    'sqlite-libs-3.26.0-13.el8',
    'sqlite-libs-debuginfo-3.26.0-13.el8',
    'sqlite-tcl-3.26.0-13.el8',
    'sqlite-tcl-debuginfo-3.26.0-13.el8'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'sqlite');
}

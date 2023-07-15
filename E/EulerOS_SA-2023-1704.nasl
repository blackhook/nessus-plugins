#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175168);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/07");

  script_cve_id(
    "CVE-2021-46657",
    "CVE-2021-46661",
    "CVE-2021-46662",
    "CVE-2021-46663",
    "CVE-2021-46665",
    "CVE-2021-46666",
    "CVE-2021-46667",
    "CVE-2021-46668",
    "CVE-2022-27383",
    "CVE-2022-27386",
    "CVE-2022-27455",
    "CVE-2022-27457",
    "CVE-2022-31624"
  );

  script_name(english:"EulerOS Virtualization 3.0.2.0 : mariadb (EulerOS-SA-2023-1704)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the mariadb packages installed, the EulerOS Virtualization installation on the remote host
is affected by the following vulnerabilities :

  - get_sort_by_table in MariaDB before 10.6.2 allows an application crash via certain subquery uses of ORDER
    BY. (CVE-2021-46657)

  - MariaDB through 10.5.9 allows an application crash in find_field_in_tables and find_order_in_list via an
    unused common table expression (CTE). (CVE-2021-46661)

  - MariaDB through 10.5.9 allows a set_var.cc application crash via certain uses of an UPDATE statement in
    conjunction with a nested subquery. (CVE-2021-46662)

  - MariaDB through 10.5.13 allows a ha_maria::extra application crash via certain SELECT statements.
    (CVE-2021-46663)

  - MariaDB through 10.5.9 allows a sql_parse.cc application crash because of incorrect used_tables
    expectations. (CVE-2021-46665)

  - MariaDB before 10.6.2 allows an application crash because of mishandling of a pushdown from a HAVING
    clause to a WHERE clause. (CVE-2021-46666)

  - MariaDB before 10.6.5 has a sql_lex.cc integer overflow, leading to an application crash. (CVE-2021-46667)

  - MariaDB through 10.5.9 allows an application crash via certain long SELECT DISTINCT statements that
    improperly interact with storage-engine resource limitations for temporary data structures.
    (CVE-2021-46668)

  - MariaDB Server v10.6 and below was discovered to contain an use-after-free in the component
    my_strcasecmp_8bit, which is exploited via specially crafted SQL statements. (CVE-2022-27383)

  - MariaDB Server v10.7 and below was discovered to contain a segmentation fault via the component
    sql/sql_class.cc. (CVE-2022-27386)

  - MariaDB Server v10.6.3 and below was discovered to contain an use-after-free in the component
    my_wildcmp_8bit_impl at /strings/ctype-simple.c. (CVE-2022-27455)

  - MariaDB Server v10.6.3 and below was discovered to contain an use-after-free in the component
    my_mb_wc_latin1 at /strings/ctype-latin1.c. (CVE-2022-27457)

  - MariaDB Server before 10.7 is vulnerable to Denial of Service. While executing the
    plugin/server_audit/server_audit.c method log_statement_ex, the held lock lock_bigbuffer is not released
    correctly, which allows local users to trigger a denial of service due to the deadlock. (CVE-2022-31624)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1704
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d66264c5");
  script_set_attribute(attribute:"solution", value:
"Update the affected mariadb packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27457");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "mariadb-5.5.66-1.h6",
  "mariadb-libs-5.5.66-1.h6",
  "mariadb-server-5.5.66-1.h6"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb");
}

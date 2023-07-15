##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4639-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143119);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2018-7260",
    "CVE-2018-19968",
    "CVE-2018-19970",
    "CVE-2019-6798",
    "CVE-2019-6799",
    "CVE-2019-11768",
    "CVE-2019-12616",
    "CVE-2020-5504",
    "CVE-2020-10802",
    "CVE-2020-10803",
    "CVE-2020-10804",
    "CVE-2020-26934",
    "CVE-2020-26935"
  );
  script_bugtraq_id(
    103099,
    106178,
    106181,
    106727,
    106736,
    108617,
    108619
  );
  script_xref(name:"USN", value:"4639-1");

  script_name(english:"Ubuntu 18.04 LTS : phpMyAdmin vulnerabilities (USN-4639-1)");
  script_summary(english:"Checks the dpkg output for the updated package");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-4639-1 advisory.

  - Cross-site scripting (XSS) vulnerability in db_central_columns.php in phpMyAdmin before 4.7.8 allows
    remote authenticated users to inject arbitrary web script or HTML via a crafted URL. (CVE-2018-7260)

  - An attacker can exploit phpMyAdmin before 4.8.4 to leak the contents of a local file because of an error
    in the transformation feature. The attacker must have access to the phpMyAdmin Configuration Storage
    tables, although these can easily be created in any database to which the attacker has access. An attacker
    must have valid credentials to log in to phpMyAdmin; this vulnerability does not allow an attacker to
    circumvent the login system. (CVE-2018-19968)

  - In phpMyAdmin before 4.8.4, an XSS vulnerability was found in the navigation tree, where an attacker can
    deliver a payload to a user through a crafted database/table name. (CVE-2018-19970)

  - An issue was discovered in phpMyAdmin before 4.8.5. A vulnerability was reported where a specially crafted
    username can be used to trigger a SQL injection attack through the designer feature. (CVE-2019-6798)

  - An issue was discovered in phpMyAdmin before 4.8.5. When the AllowArbitraryServer configuration setting is
    set to true, with the use of a rogue MySQL server, an attacker can read any file on the server that the
    web server's user can access. This is related to the mysql.allow_local_infile PHP configuration, and the
    inadvertent ignoring of options(MYSQLI_OPT_LOCAL_INFILE calls. (CVE-2019-6799)

  - An issue was discovered in phpMyAdmin before 4.9.0.1. A vulnerability was reported where a specially
    crafted database name can be used to trigger an SQL injection attack through the designer feature.
    (CVE-2019-11768)

  - An issue was discovered in phpMyAdmin before 4.9.0. A vulnerability was found that allows an attacker to
    trigger a CSRF attack against a phpMyAdmin user. The attacker can trick the user, for instance through a
    broken  tag pointing at the victim's phpMyAdmin database, and the attacker can potentially deliver a
    payload (such as a specific INSERT or DELETE statement) to the victim. (CVE-2019-12616)

  - In phpMyAdmin 4 before 4.9.4 and 5 before 5.0.1, SQL injection exists in the user accounts page. A
    malicious user could inject custom SQL in place of their own username when creating queries to this page.
    An attacker must have a valid MySQL account to access the server. (CVE-2020-5504)

  - In phpMyAdmin 4.x before 4.9.5 and 5.x before 5.0.2, a SQL injection vulnerability has been discovered
    where certain parameters are not properly escaped when generating certain queries for search actions in
    libraries/classes/Controllers/Table/TableSearchController.php. An attacker can generate a crafted database
    or table name. The attack can be performed if a user attempts certain search operations on the malicious
    database or table. (CVE-2020-10802)

  - In phpMyAdmin 4.x before 4.9.5 and 5.x before 5.0.2, a SQL injection vulnerability was discovered where
    malicious code could be used to trigger an XSS attack through retrieving and displaying results (in
    tbl_get_field.php and libraries/classes/Display/Results.php). The attacker must be able to insert crafted
    data into certain database tables, which when retrieved (for instance, through the Browse tab) can trigger
    the XSS attack. (CVE-2020-10803)

  - In phpMyAdmin 4.x before 4.9.5 and 5.x before 5.0.2, a SQL injection vulnerability was found in retrieval
    of the current username (in libraries/classes/Server/Privileges.php and
    libraries/classes/UserPassword.php). A malicious user with access to the server could create a crafted
    username, and then trick the victim into performing specific actions with that user account (such as
    editing its privileges). (CVE-2020-10804)

  - phpMyAdmin before 4.9.6 and 5.x before 5.0.3 allows XSS through the transformation feature via a crafted
    link. (CVE-2020-26934)

  - An issue was discovered in SearchController in phpMyAdmin before 4.9.6 and 5.x before 5.0.3. A SQL
    injection vulnerability was discovered in how phpMyAdmin processes SQL statements in the search feature.
    An attacker could use this flaw to inject malicious SQL in to a query. (CVE-2020-26935)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4639-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected phpmyadmin package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26935");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(18\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '18.04', 'pkgname': 'phpmyadmin', 'pkgver': '4:4.6.6-5ubuntu0.5'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'phpmyadmin');
}
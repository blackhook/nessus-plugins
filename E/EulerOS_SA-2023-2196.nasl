#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177004);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/30");

  script_cve_id(
    "CVE-2023-0567",
    "CVE-2023-0568",
    "CVE-2023-0662",
    "CVE-2023-28708"
  );
  script_xref(name:"IAVA", value:"2023-A-0105-S");

  script_name(english:"EulerOS 2.0 SP8 : php (EulerOS-SA-2023-2196)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the php packages installed, the EulerOS installation on the remote host is affected by the
following vulnerabilities :

  - In PHP 8.0.X before 8.0.28, 8.1.X before 8.1.16 and 8.2.X before 8.2.3, password_verify() function may
    accept some invalid Blowfish hashes as valid. If such invalid hash ever ends up in the password database,
    it may lead to an application allowing any password for this entry as valid. (CVE-2023-0567)

  - In PHP 8.0.X before 8.0.28, 8.1.X before 8.1.16 and 8.2.X before 8.2.3, core path resolution function
    allocate buffer one byte too small. When resolving paths with lengths close to system MAXPATHLEN setting,
    this may lead to the byte after the allocated buffer being overwritten with NUL value, which might lead to
    unauthorized data access or modification. (CVE-2023-0568)

  - In PHP 8.0.X before 8.0.28, 8.1.X before 8.1.16 and 8.2.X before 8.2.3, excessive number of parts in HTTP
    form upload can cause high resource consumption and excessive number of log entries. This can cause denial
    of service on the affected server by exhausting CPU resources or disk space. (CVE-2023-0662)

  - When using the RemoteIpFilter with requests received from a reverse proxy via HTTP that include the
    X-Forwarded-Proto header set to https, session cookies created by Apache Tomcat 11.0.0-M1 to 11.0.0.-M2,
    10.1.0-M1 to 10.1.5, 9.0.0-M1 to 9.0.71 and 8.5.0 to 8.5.85 did not include the secure attribute. This
    could result in the user agent transmitting the session cookie over an insecure channel. (CVE-2023-28708)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2196
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8f77736");
  script_set_attribute(attribute:"solution", value:
"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0568");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "php-7.2.10-1.h34.eulerosv2r8",
  "php-cli-7.2.10-1.h34.eulerosv2r8",
  "php-common-7.2.10-1.h34.eulerosv2r8",
  "php-fpm-7.2.10-1.h34.eulerosv2r8",
  "php-gd-7.2.10-1.h34.eulerosv2r8",
  "php-ldap-7.2.10-1.h34.eulerosv2r8",
  "php-odbc-7.2.10-1.h34.eulerosv2r8",
  "php-pdo-7.2.10-1.h34.eulerosv2r8",
  "php-process-7.2.10-1.h34.eulerosv2r8",
  "php-recode-7.2.10-1.h34.eulerosv2r8",
  "php-soap-7.2.10-1.h34.eulerosv2r8",
  "php-xml-7.2.10-1.h34.eulerosv2r8",
  "php-xmlrpc-7.2.10-1.h34.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}

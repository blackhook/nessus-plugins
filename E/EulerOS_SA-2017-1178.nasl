#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103016);
  script_version("3.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-3167",
    "CVE-2017-3169",
    "CVE-2017-7668",
    "CVE-2017-7679",
    "CVE-2017-9788"
  );

  script_name(english:"EulerOS 2.0 SP2 : httpd (EulerOS-SA-2017-1178)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the httpd packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - It was discovered that the httpd's mod_auth_digest
    module did not properly initialize memory before using
    it when processing certain headers related to digest
    authentication. A remote attacker could possibly use
    this flaw to disclose potentially sensitive information
    or cause httpd child process to crash by sending
    specially crafted requests to a server. (CVE-2017-9788)

  - It was discovered that the use of httpd's
    ap_get_basic_auth_pw() API function outside of the
    authentication phase could lead to authentication
    bypass. A remote attacker could possibly use this flaw
    to bypass required authentication if the API was used
    incorrectly by one of the modules used by httpd.
    (CVE-2017-3167)

  - A NULL pointer dereference flaw was found in the
    httpd's mod_ssl module. A remote attacker could use
    this flaw to cause an httpd child process to crash if
    another module used by httpd called a certain API
    function during the processing of an HTTPS request.
    (CVE-2017-3169)

  - A buffer over-read flaw was found in the httpd's
    ap_find_token() function. A remote attacker could use
    this flaw to cause httpd child process to crash via a
    specially crafted HTTP request. (CVE-2017-7668)

  - A buffer over-read flaw was found in the httpd's
    mod_mime module. A user permitted to modify httpd's
    MIME configuration could use this flaw to cause httpd
    child process to crash. (CVE-2017-7679)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1178
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36c8a96a");
  script_set_attribute(attribute:"solution", value:
"Update the affected httpd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["httpd-2.4.6-45.0.1.4.h4",
        "httpd-devel-2.4.6-45.0.1.4.h4",
        "httpd-manual-2.4.6-45.0.1.4.h4",
        "httpd-tools-2.4.6-45.0.1.4.h4"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd");
}

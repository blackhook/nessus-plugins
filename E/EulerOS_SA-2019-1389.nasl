#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124892);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-3167",
    "CVE-2017-3169",
    "CVE-2017-7668",
    "CVE-2017-7679",
    "CVE-2017-9788",
    "CVE-2017-9798",
    "CVE-2018-17199"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : httpd (EulerOS-SA-2019-1389)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the httpd packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - In Apache HTTP Server 2.4 release 2.4.37 and prior,
    mod_session checks the session expiry time before
    decoding the session. This causes session expiry time
    to be ignored for mod_session_cookie sessions since the
    expiry time is loaded when the session is
    decoded.(CVE-2018-17199)

  - It was discovered that the use of httpd's
    ap_get_basic_auth_pw() API function outside of the
    authentication phase could lead to authentication
    bypass. A remote attacker could possibly use this flaw
    to bypass required authentication if the API was used
    incorrectly by one of the modules used by
    httpd.(CVE-2017-3167)

  - A NULL pointer dereference flaw was found in the
    httpd's mod_ssl module. A remote attacker could use
    this flaw to cause an httpd child process to crash if
    another module used by httpd called a certain API
    function during the processing of an HTTPS
    request.(CVE-2017-3169)

  - A buffer over-read flaw was found in the httpd's
    ap_find_token() function. A remote attacker could use
    this flaw to cause httpd child process to crash via a
    specially crafted HTTP request.(CVE-2017-7668)

  - A buffer over-read flaw was found in the httpd's
    mod_mime module. A user permitted to modify httpd's
    MIME configuration could use this flaw to cause httpd
    child process to crash.(CVE-2017-7679)

  - It was discovered that the httpd's mod_auth_digest
    module did not properly initialize memory before using
    it when processing certain headers related to digest
    authentication. A remote attacker could possibly use
    this flaw to disclose potentially sensitive information
    or cause httpd child process to crash by sending
    specially crafted requests to a server.(CVE-2017-9788)

  - A use-after-free flaw was found in the way httpd
    handled invalid and previously unregistered HTTP
    methods specified in the Limit directive used in an
    .htaccess file. A remote attacker could possibly use
    this flaw to disclose portions of the server memory, or
    cause httpd child process to crash.(CVE-2017-9798)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1389
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5abd589d");
  script_set_attribute(attribute:"solution", value:
"Update the affected httpd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["httpd-2.4.6-80.1.h4",
        "httpd-tools-2.4.6-80.1.h4",
        "mod_ssl-2.4.6-80.1.h4"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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

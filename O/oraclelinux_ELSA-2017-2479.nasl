#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2017:2479 and 
# Oracle Linux Security Advisory ELSA-2017-2479 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102515);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-3167", "CVE-2017-3169", "CVE-2017-7668", "CVE-2017-7679", "CVE-2017-9788");
  script_xref(name:"RHSA", value:"2017:2479");

  script_name(english:"Oracle Linux 7 : httpd (ELSA-2017-2479)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2017:2479 :

An update for httpd is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The httpd packages provide the Apache HTTP Server, a powerful,
efficient, and extensible web server.

Security Fix(es) :

* It was discovered that the httpd's mod_auth_digest module did not
properly initialize memory before using it when processing certain
headers related to digest authentication. A remote attacker could
possibly use this flaw to disclose potentially sensitive information
or cause httpd child process to crash by sending specially crafted
requests to a server. (CVE-2017-9788)

* It was discovered that the use of httpd's ap_get_basic_auth_pw() API
function outside of the authentication phase could lead to
authentication bypass. A remote attacker could possibly use this flaw
to bypass required authentication if the API was used incorrectly by
one of the modules used by httpd. (CVE-2017-3167)

* A NULL pointer dereference flaw was found in the httpd's mod_ssl
module. A remote attacker could use this flaw to cause an httpd child
process to crash if another module used by httpd called a certain API
function during the processing of an HTTPS request. (CVE-2017-3169)

* A buffer over-read flaw was found in the httpd's ap_find_token()
function. A remote attacker could use this flaw to cause httpd child
process to crash via a specially crafted HTTP request. (CVE-2017-7668)

* A buffer over-read flaw was found in the httpd's mod_mime module. A
user permitted to modify httpd's MIME configuration could use this
flaw to cause httpd child process to crash. (CVE-2017-7679)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-August/007126.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"httpd-2.4.6-67.0.1.el7_4.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"httpd-devel-2.4.6-67.0.1.el7_4.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"httpd-manual-2.4.6-67.0.1.el7_4.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"httpd-tools-2.4.6-67.0.1.el7_4.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mod_ldap-2.4.6-67.0.1.el7_4.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mod_proxy_html-2.4.6-67.0.1.el7_4.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mod_session-2.4.6-67.0.1.el7_4.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mod_ssl-2.4.6-67.0.1.el7_4.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-devel / httpd-manual / httpd-tools / mod_ldap / etc");
}

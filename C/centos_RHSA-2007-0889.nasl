#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0889 and 
# CentOS Errata and Security Advisory 2007:0889 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(26204);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-2509", "CVE-2007-2756", "CVE-2007-2872", "CVE-2007-3799", "CVE-2007-3996", "CVE-2007-3998", "CVE-2007-4658", "CVE-2007-4670");
  script_bugtraq_id(22764, 23813, 23818, 24089, 24261, 24268, 25498);
  script_xref(name:"RHSA", value:"2007:0889");

  script_name(english:"CentOS 3 : php (CESA-2007:0889)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated PHP packages that fix several security issues are now
available for Red Hat Enterprise Linux 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Web server.

These updated packages address the following vulnerabilities :

Various integer overflow flaws were found in the PHP gd extension
script that could be forced to resize images from an untrusted source,
possibly allowing a remote attacker to execute arbitrary code as the
apache user. (CVE-2007-3996)

An integer overflow flaw was found in the PHP chunk_split function. If
a remote attacker was able to pass arbitrary data to the third
argument of chunk_split they could possibly execute arbitrary code as
the apache user. Note that it is unusual for a PHP script to use the
chunk_split function with a user-supplied third argument.
(CVE-2007-2872)

A previous security update introduced a bug into PHP session cookie
handling. This could allow an attacker to stop a victim from viewing a
vulnerable website if the victim has first visited a malicious web
page under the control of the attacker, and that page can set a cookie
for the vulnerable website. (CVE-2007-4670)

A flaw was found in the PHP money_format function. If a remote
attacker was able to pass arbitrary data to the money_format function
this could possibly result in an information leak or denial of
service. Note that it is unusual for a PHP script to pass
user-supplied data to the money_format function. (CVE-2007-4658)

A flaw was found in the PHP wordwrap function. If a remote attacker
was able to pass arbitrary data to the wordwrap function this could
possibly result in a denial of service. (CVE-2007-3998)

A bug was found in PHP session cookie handling. This could allow an
attacker to create a cross-site cookie insertion attack if a victim
follows an untrusted carefully-crafted URL. (CVE-2007-3799)

An infinite-loop flaw was discovered in the PHP gd extension. A script
that could be forced to process PNG images from an untrusted source
could allow a remote attacker to cause a denial of service.
(CVE-2007-2756)

A flaw was found in the PHP 'ftp' extension. If a PHP script used this
extension to provide access to a private FTP server, and passed
untrusted script input directly to any function provided by this
extension, a remote attacker would be able to send arbitrary FTP
commands to the server. (CVE-2007-2509)

Users of PHP should upgrade to these updated packages, which contain
backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-September/014237.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d7b0dcbf"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-September/014242.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?481ce183"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-September/014243.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?73d2c0d0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"php-4.3.2-43.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-devel-4.3.2-43.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-imap-4.3.2-43.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-ldap-4.3.2-43.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-mysql-4.3.2-43.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-odbc-4.3.2-43.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-pgsql-4.3.2-43.ent")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-devel / php-imap / php-ldap / php-mysql / php-odbc / etc");
}

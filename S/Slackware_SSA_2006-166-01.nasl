#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2006-166-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21699);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2006-1173");
  script_xref(name:"SSA", value:"2006-166-01");

  script_name(english:"Slackware 10.0 / 10.1 / 10.2 / 8.1 / 9.0 / 9.1 / current : sendmail (SSA:2006-166-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New sendmail packages are available for Slackware 8.1, 9.0, 9.1,
10.0, 10.1, 10.2, and -current to fix a possible denial-of-service
issue. Sendmail's complete advisory may be found here:
http://www.sendmail.com/security/advisories/SA-200605-01.txt.asc
Sendmail has also provided an FAQ about this issue:
http://www.sendmail.com/security/advisories/SA-200605-01/faq.shtml The
CVE entry for this issue may be found here:
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1173"
  );
  # http://www.sendmail.com/security/advisories/SA-200605-01.txt.asc
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.proofpoint.com/us/products/mail-routing-agent"
  );
  # http://www.sendmail.com/security/advisories/SA-200605-01/faq.shtml
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.proofpoint.com/us/products/mail-routing-agent"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.631382
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27f050e4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sendmail and / or sendmail-cf packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:sendmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:sendmail-cf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Slackware Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("slackware.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);


flag = 0;
if (slackware_check(osver:"8.1", pkgname:"sendmail", pkgver:"8.13.7", pkgarch:"i386", pkgnum:"1_slack8.1")) flag++;
if (slackware_check(osver:"8.1", pkgname:"sendmail-cf", pkgver:"8.13.7", pkgarch:"noarch", pkgnum:"1_slack8.1")) flag++;

if (slackware_check(osver:"9.0", pkgname:"sendmail", pkgver:"8.13.7", pkgarch:"i386", pkgnum:"1_slack9.0")) flag++;
if (slackware_check(osver:"9.0", pkgname:"sendmail-cf", pkgver:"8.13.7", pkgarch:"noarch", pkgnum:"1_slack9.0")) flag++;

if (slackware_check(osver:"9.1", pkgname:"sendmail", pkgver:"8.13.7", pkgarch:"i486", pkgnum:"1_slack9.1")) flag++;
if (slackware_check(osver:"9.1", pkgname:"sendmail-cf", pkgver:"8.13.7", pkgarch:"noarch", pkgnum:"1_slack9.1")) flag++;

if (slackware_check(osver:"10.0", pkgname:"sendmail", pkgver:"8.13.7", pkgarch:"i486", pkgnum:"1_slack10.0")) flag++;
if (slackware_check(osver:"10.0", pkgname:"sendmail-cf", pkgver:"8.13.7", pkgarch:"noarch", pkgnum:"1_slack10.0")) flag++;

if (slackware_check(osver:"10.1", pkgname:"sendmail", pkgver:"8.13.7", pkgarch:"i486", pkgnum:"1_slack10.1")) flag++;
if (slackware_check(osver:"10.1", pkgname:"sendmail-cf", pkgver:"8.13.7", pkgarch:"noarch", pkgnum:"1_slack10.1")) flag++;

if (slackware_check(osver:"10.2", pkgname:"sendmail", pkgver:"8.13.7", pkgarch:"i486", pkgnum:"1_slack10.2")) flag++;
if (slackware_check(osver:"10.2", pkgname:"sendmail-cf", pkgver:"8.13.7", pkgarch:"noarch", pkgnum:"1_slack10.2")) flag++;

if (slackware_check(osver:"current", pkgname:"sendmail", pkgver:"8.13.7", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"sendmail-cf", pkgver:"8.13.7", pkgarch:"noarch", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

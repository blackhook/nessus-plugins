#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2012-098-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59478);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-1173");
  script_xref(name:"SSA", value:"2012-098-01");

  script_name(english:"Slackware 10.0 / 10.1 / 10.2 / 11.0 / 12.0 / 12.1 / 12.2 / 13.0 / 13.1 / 13.37 / 9.0 / 9.1 / current : libtiff (SSA:2012-098-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New libtiff packages are available for Slackware 9.0, 9.1, 10.0,
10.1, 10.2, 11.0, 12.0, 12.1, 12.2, 13.0, 13.1, 13.37, and -current to
fix security issues."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2012&m=slackware-security.120407
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?77358a00"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtiff package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:libtiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.37");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (slackware_check(osver:"9.0", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i386", pkgnum:"4_slack9.0")) flag++;

if (slackware_check(osver:"9.1", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i486", pkgnum:"4_slack9.1")) flag++;

if (slackware_check(osver:"10.0", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i486", pkgnum:"4_slack10.0")) flag++;

if (slackware_check(osver:"10.1", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i486", pkgnum:"4_slack10.1")) flag++;

if (slackware_check(osver:"10.2", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i486", pkgnum:"4_slack10.2")) flag++;

if (slackware_check(osver:"11.0", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i486", pkgnum:"5_slack11.0")) flag++;

if (slackware_check(osver:"12.0", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i486", pkgnum:"6_slack12.0")) flag++;

if (slackware_check(osver:"12.1", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i486", pkgnum:"6_slack12.1")) flag++;

if (slackware_check(osver:"12.2", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i486", pkgnum:"6_slack12.2")) flag++;

if (slackware_check(osver:"13.0", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"i486", pkgnum:"6_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"libtiff", pkgver:"3.8.2", pkgarch:"x86_64", pkgnum:"6_slack13.0")) flag++;

if (slackware_check(osver:"13.1", pkgname:"libtiff", pkgver:"3.9.6", pkgarch:"i486", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"libtiff", pkgver:"3.9.6", pkgarch:"x86_64", pkgnum:"1_slack13.1")) flag++;

if (slackware_check(osver:"13.37", pkgname:"libtiff", pkgver:"3.9.6", pkgarch:"i486", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"libtiff", pkgver:"3.9.6", pkgarch:"x86_64", pkgnum:"1_slack13.37")) flag++;

if (slackware_check(osver:"current", pkgname:"libtiff", pkgver:"3.9.6", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"libtiff", pkgver:"3.9.6", pkgarch:"x86_64", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

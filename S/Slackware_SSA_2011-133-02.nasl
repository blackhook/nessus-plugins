#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2011-133-02. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(53899);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_xref(name:"SSA", value:"2011-133-02");

  script_name(english:"Slackware 12.0 / 12.1 / 12.2 / 13.0 / 13.1 / 13.37 / current : httpd (SSA:2011-133-02)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New httpd packages are available for Slackware 12.0, 12.1, 12.2,
13.0, 13.1, 13.37, and -current. These have been compiled against the
new versions of apr and apr-util, which were upgraded to fix a
security issue that affects Apache httpd. It is recommended that all
three updates be applied."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2011&m=slackware-security.520671
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?156f73b9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected httpd package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.37");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"12.0", pkgname:"httpd", pkgver:"2.2.18", pkgarch:"i486", pkgnum:"1_slack12.0")) flag++;

if (slackware_check(osver:"12.1", pkgname:"httpd", pkgver:"2.2.18", pkgarch:"i486", pkgnum:"1_slack12.1")) flag++;

if (slackware_check(osver:"12.2", pkgname:"httpd", pkgver:"2.2.18", pkgarch:"i486", pkgnum:"1_slack12.2")) flag++;

if (slackware_check(osver:"13.0", pkgname:"httpd", pkgver:"2.2.18", pkgarch:"i486", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"httpd", pkgver:"2.2.18", pkgarch:"x86_64", pkgnum:"1_slack13.0")) flag++;

if (slackware_check(osver:"13.1", pkgname:"httpd", pkgver:"2.2.18", pkgarch:"i486", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"httpd", pkgver:"2.2.18", pkgarch:"x86_64", pkgnum:"1_slack13.1")) flag++;

if (slackware_check(osver:"13.37", pkgname:"httpd", pkgver:"2.2.18", pkgarch:"i486", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"httpd", pkgver:"2.2.18", pkgarch:"x86_64", pkgnum:"1_slack13.37")) flag++;

if (slackware_check(osver:"current", pkgname:"httpd", pkgver:"2.2.18", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"httpd", pkgver:"2.2.18", pkgarch:"x86_64", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2018-212-02. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111499);
  script_version("1.2");
  script_cvs_date("Date: 2018/08/02 16:41:58");

  script_xref(name:"SSA", value:"2018-212-02");

  script_name(english:"Slackware 14.0 / 14.1 / 14.2 / current : seamonkey (SSA:2018-212-02)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New seamonkey packages are available for Slackware 14.2 and -current
to fix security issues."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2018&m=slackware-security.562481
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a4d3bce7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey and / or seamonkey-solibs packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:seamonkey-solibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (slackware_check(osver:"14.0", pkgname:"seamonkey", pkgver:"2.38", pkgarch:"i486", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", pkgname:"seamonkey-solibs", pkgver:"2.38", pkgarch:"i486", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"seamonkey", pkgver:"2.38", pkgarch:"x86_64", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"seamonkey-solibs", pkgver:"2.38", pkgarch:"x86_64", pkgnum:"1_slack14.0")) flag++;

if (slackware_check(osver:"14.1", pkgname:"seamonkey", pkgver:"2.46", pkgarch:"i486", pkgnum:"3_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"seamonkey-solibs", pkgver:"2.46", pkgarch:"i486", pkgnum:"3_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"seamonkey", pkgver:"2.46", pkgarch:"x86_64", pkgnum:"3_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"seamonkey-solibs", pkgver:"2.46", pkgarch:"x86_64", pkgnum:"3_slack14.1")) flag++;

if (slackware_check(osver:"14.2", pkgname:"seamonkey", pkgver:"2.49.4", pkgarch:"i586", pkgnum:"1_slack14.2")) flag++;
if (slackware_check(osver:"14.2", pkgname:"seamonkey-solibs", pkgver:"2.49.4", pkgarch:"i586", pkgnum:"1_slack14.2")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"seamonkey", pkgver:"2.49.4", pkgarch:"x86_64", pkgnum:"1_slack14.2")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"seamonkey-solibs", pkgver:"2.49.4", pkgarch:"x86_64", pkgnum:"1_slack14.2")) flag++;

if (slackware_check(osver:"current", pkgname:"seamonkey", pkgver:"2.49.4", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"seamonkey-solibs", pkgver:"2.49.4", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"seamonkey", pkgver:"2.49.4", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"seamonkey-solibs", pkgver:"2.49.4", pkgarch:"x86_64", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

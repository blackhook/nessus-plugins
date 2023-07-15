#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2007-283-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(26972);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_xref(name:"SSA", value:"2007-283-01");

  script_name(english:"Slackware 10.0 / 10.1 / 10.2 / 11.0 / 12.0 / 8.1 / 9.0 / 9.1 : glibc-zoneinfo (SSA:2007-283-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New glibc-zoneinfo packages are available for Slackware 8.1, 9.0,
9.1, 10.0, 10.1, 10.2, 11.0, and 12.0 to update the timezone tables to
the latest versions. If you've noticed your clock has wandered off,
these packages should fix the problem. This isn't really a 'security
issue' (or is a minor one), but it's an important fix nevertheless."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2007&m=slackware-security.483739
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3424d872"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc-zoneinfo package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-zoneinfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"8.1", pkgname:"glibc-zoneinfo", pkgver:"2.2.5", pkgarch:"i386", pkgnum:"4_slack8.1")) flag++;

if (slackware_check(osver:"9.0", pkgname:"glibc-zoneinfo", pkgver:"2.3.1", pkgarch:"noarch", pkgnum:"6_slack9.0")) flag++;

if (slackware_check(osver:"9.1", pkgname:"glibc-zoneinfo", pkgver:"2.3.2", pkgarch:"noarch", pkgnum:"3_slack9.1")) flag++;

if (slackware_check(osver:"10.0", pkgname:"glibc-zoneinfo", pkgver:"2.3.2", pkgarch:"noarch", pkgnum:"8_slack10.0")) flag++;

if (slackware_check(osver:"10.1", pkgname:"glibc-zoneinfo", pkgver:"2.3.4", pkgarch:"noarch", pkgnum:"3_slack10.1")) flag++;

if (slackware_check(osver:"10.2", pkgname:"glibc-zoneinfo", pkgver:"2.3.5", pkgarch:"noarch", pkgnum:"8_slack10.2")) flag++;

if (slackware_check(osver:"11.0", pkgname:"glibc-zoneinfo", pkgver:"2.3.6", pkgarch:"noarch", pkgnum:"8_slack11.0")) flag++;

if (slackware_check(osver:"12.0", pkgname:"glibc-zoneinfo", pkgver:"2.5", pkgarch:"noarch", pkgnum:"5_slack12.0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
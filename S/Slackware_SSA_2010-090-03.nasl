#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2010-090-03. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(54877);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_xref(name:"SSA", value:"2010-090-03");

  script_name(english:"Slackware 11.0 / 12.0 / 12.1 : seamonkey (SSA:2010-090-03)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New seamonkey packages are available for Slackware 11.0, 12.0, and
12.1 to fix security issues."
  );
  # http://www.mozilla.org/security/known-vulnerabilities/seamonkey11.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e868d512"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2010&m=slackware-security.362028
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9fee5690"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (slackware_check(osver:"11.0", pkgname:"seamonkey", pkgver:"1.1.19", pkgarch:"i486", pkgnum:"1_slack11.0")) flag++;

if (slackware_check(osver:"12.0", pkgname:"seamonkey", pkgver:"1.1.19", pkgarch:"i486", pkgnum:"1_slack12.0")) flag++;

if (slackware_check(osver:"12.1", pkgname:"seamonkey", pkgver:"1.1.19", pkgarch:"i486", pkgnum:"1_slack12.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

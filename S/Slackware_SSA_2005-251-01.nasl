#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2005-251-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(19861);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2005-2494");
  script_xref(name:"SSA", value:"2005-251-01");

  script_name(english:"Slackware 10.0 / 10.1 / current : kcheckpass in kdebase (SSA:2005-251-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New kdebase packages are available for Slackware 10.0, 10.1, and
-current to fix a security issue with the kcheckpass program. Earlier
versions of Slackware are not affected. A flaw in the way the program
creates lockfiles could allow a local attacker to gain root
privileges."
  );
  # http://www.kde.org/info/security/advisory-20050905-1.txt
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.kde.org/info/security/advisory-20050905-1.txt"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2005&m=slackware-security.367371
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?700a2028"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdebase package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (slackware_check(osver:"10.0", pkgname:"kdebase", pkgver:"3.2.3", pkgarch:"i486", pkgnum:"3")) flag++;

if (slackware_check(osver:"10.1", pkgname:"kdebase", pkgver:"3.3.2", pkgarch:"i486", pkgnum:"2")) flag++;

if (slackware_check(osver:"current", pkgname:"kdebase", pkgver:"3.4.2", pkgarch:"i486", pkgnum:"2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

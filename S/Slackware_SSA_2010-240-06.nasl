#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2010-240-06. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(48923);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-2240");
  script_bugtraq_id(42505);
  script_xref(name:"SSA", value:"2010-240-06");

  script_name(english:"Slackware 12.0 / 12.1 / 12.2 / 13.0 / 13.1 / current : xorg-server (SSA:2010-240-06)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New xorg-server packages are available for Slackware 12.0, 12.1,
12.2, 13.0, 13.1, and -current to fix a security issue."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2010&m=slackware-security.881486
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e0806341"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xorg-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xorg-server-xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xorg-server-xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xorg-server-xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xorg-server-xvfb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"12.0", pkgname:"xorg-server", pkgver:"1.3.0.0", pkgarch:"i486", pkgnum:"3_slack12.0")) flag++;
if (slackware_check(osver:"12.0", pkgname:"xorg-server-xdmx", pkgver:"1.3.0.0", pkgarch:"i486", pkgnum:"3_slack12.0")) flag++;
if (slackware_check(osver:"12.0", pkgname:"xorg-server-xnest", pkgver:"1.3.0.0", pkgarch:"i486", pkgnum:"3_slack12.0")) flag++;
if (slackware_check(osver:"12.0", pkgname:"xorg-server-xvfb", pkgver:"1.3.0.0", pkgarch:"i486", pkgnum:"3_slack12.0")) flag++;

if (slackware_check(osver:"12.1", pkgname:"xorg-server", pkgver:"1.4.2", pkgarch:"i486", pkgnum:"2_slack12.1")) flag++;
if (slackware_check(osver:"12.1", pkgname:"xorg-server-xnest", pkgver:"1.4.2", pkgarch:"i486", pkgnum:"2_slack12.1")) flag++;
if (slackware_check(osver:"12.1", pkgname:"xorg-server-xvfb", pkgver:"1.4.2", pkgarch:"i486", pkgnum:"2_slack12.1")) flag++;

if (slackware_check(osver:"12.2", pkgname:"xorg-server", pkgver:"1.4.2", pkgarch:"i486", pkgnum:"2_slack12.2")) flag++;
if (slackware_check(osver:"12.2", pkgname:"xorg-server-xnest", pkgver:"1.4.2", pkgarch:"i486", pkgnum:"2_slack12.2")) flag++;
if (slackware_check(osver:"12.2", pkgname:"xorg-server-xvfb", pkgver:"1.4.2", pkgarch:"i486", pkgnum:"2_slack12.2")) flag++;

if (slackware_check(osver:"13.0", pkgname:"xorg-server", pkgver:"1.6.3", pkgarch:"i486", pkgnum:"2_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"xorg-server-xephyr", pkgver:"1.6.3", pkgarch:"i486", pkgnum:"2_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"xorg-server-xnest", pkgver:"1.6.3", pkgarch:"i486", pkgnum:"2_slack13.0")) flag++;
if (slackware_check(osver:"13.0", pkgname:"xorg-server-xvfb", pkgver:"1.6.3", pkgarch:"i486", pkgnum:"2_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"xorg-server", pkgver:"1.6.3", pkgarch:"x86_64", pkgnum:"2_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"xorg-server-xephyr", pkgver:"1.6.3", pkgarch:"x86_64", pkgnum:"2_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"xorg-server-xnest", pkgver:"1.6.3", pkgarch:"x86_64", pkgnum:"2_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"xorg-server-xvfb", pkgver:"1.6.3", pkgarch:"x86_64", pkgnum:"2_slack13.0")) flag++;

if (slackware_check(osver:"13.1", pkgname:"xorg-server", pkgver:"1.7.7", pkgarch:"i486", pkgnum:"2_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"xorg-server-xephyr", pkgver:"1.7.7", pkgarch:"i486", pkgnum:"2_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"xorg-server-xnest", pkgver:"1.7.7", pkgarch:"i486", pkgnum:"2_slack13.1")) flag++;
if (slackware_check(osver:"13.1", pkgname:"xorg-server-xvfb", pkgver:"1.7.7", pkgarch:"i486", pkgnum:"2_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"xorg-server", pkgver:"1.7.7", pkgarch:"x86_64", pkgnum:"2_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"xorg-server-xephyr", pkgver:"1.7.7", pkgarch:"x86_64", pkgnum:"2_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"xorg-server-xnest", pkgver:"1.7.7", pkgarch:"x86_64", pkgnum:"2_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"xorg-server-xvfb", pkgver:"1.7.7", pkgarch:"x86_64", pkgnum:"2_slack13.1")) flag++;

if (slackware_check(osver:"current", pkgname:"xorg-server", pkgver:"1.7.7", pkgarch:"i486", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", pkgname:"xorg-server-xephyr", pkgver:"1.7.7", pkgarch:"i486", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", pkgname:"xorg-server-xnest", pkgver:"1.7.7", pkgarch:"i486", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", pkgname:"xorg-server-xvfb", pkgver:"1.7.7", pkgarch:"i486", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"xorg-server", pkgver:"1.7.7", pkgarch:"x86_64", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"xorg-server-xephyr", pkgver:"1.7.7", pkgarch:"x86_64", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"xorg-server-xnest", pkgver:"1.7.7", pkgarch:"x86_64", pkgnum:"2")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"xorg-server-xvfb", pkgver:"1.7.7", pkgarch:"x86_64", pkgnum:"2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

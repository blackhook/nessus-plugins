#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2013-233-02. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(69432);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-2142");
  script_xref(name:"SSA", value:"2013-233-02");

  script_name(english:"Slackware 12.1 / 12.2 / 13.0 / 13.1 / 13.37 / 14.0 / current : xpdf (SSA:2013-233-02)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New xpdf packages are available for Slackware 12.1, 12.2, 13.0, 13.1,
13.37, 14.0, and -current to fix a security issue."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2013&m=slackware-security.496284
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aaf817e0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xpdf package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xpdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.37");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (slackware_check(osver:"12.1", pkgname:"xpdf", pkgver:"3.03", pkgarch:"i486", pkgnum:"1_slack12.1")) flag++;

if (slackware_check(osver:"12.2", pkgname:"xpdf", pkgver:"3.03", pkgarch:"i486", pkgnum:"1_slack12.2")) flag++;

if (slackware_check(osver:"13.0", pkgname:"xpdf", pkgver:"3.03", pkgarch:"i486", pkgnum:"1_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"xpdf", pkgver:"3.03", pkgarch:"x86_64", pkgnum:"1_slack13.0")) flag++;

if (slackware_check(osver:"13.1", pkgname:"xpdf", pkgver:"3.03", pkgarch:"i486", pkgnum:"1_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"xpdf", pkgver:"3.03", pkgarch:"x86_64", pkgnum:"1_slack13.1")) flag++;

if (slackware_check(osver:"13.37", pkgname:"xpdf", pkgver:"3.03", pkgarch:"i486", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"xpdf", pkgver:"3.03", pkgarch:"x86_64", pkgnum:"1_slack13.37")) flag++;

if (slackware_check(osver:"14.0", pkgname:"xpdf", pkgver:"3.03", pkgarch:"i486", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"xpdf", pkgver:"3.03", pkgarch:"x86_64", pkgnum:"1_slack14.0")) flag++;

if (slackware_check(osver:"current", pkgname:"xpdf", pkgver:"3.03", pkgarch:"i486", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"xpdf", pkgver:"3.03", pkgarch:"x86_64", pkgnum:"3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

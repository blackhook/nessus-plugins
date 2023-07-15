#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2017-181-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101169);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-1000366");
  script_xref(name:"SSA", value:"2017-181-01");

  script_name(english:"Slackware 14.2 / current : glibc (SSA:2017-181-01) (Stack Clash)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New glibc packages are available for Slackware 14.2 and -current to
fix security issues."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2017&m=slackware-security.564513
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9e86831"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:glibc-solibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/03");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (slackware_check(osver:"14.2", pkgname:"glibc", pkgver:"2.23", pkgarch:"i586", pkgnum:"2_slack14.2")) flag++;
if (slackware_check(osver:"14.2", pkgname:"glibc-i18n", pkgver:"2.23", pkgarch:"i586", pkgnum:"2_slack14.2")) flag++;
if (slackware_check(osver:"14.2", pkgname:"glibc-profile", pkgver:"2.23", pkgarch:"i586", pkgnum:"2_slack14.2")) flag++;
if (slackware_check(osver:"14.2", pkgname:"glibc-solibs", pkgver:"2.23", pkgarch:"i586", pkgnum:"2_slack14.2")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"glibc", pkgver:"2.23", pkgarch:"x86_64", pkgnum:"2_slack14.2")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"glibc-i18n", pkgver:"2.23", pkgarch:"x86_64", pkgnum:"2_slack14.2")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"glibc-profile", pkgver:"2.23", pkgarch:"x86_64", pkgnum:"2_slack14.2")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"glibc-solibs", pkgver:"2.23", pkgarch:"x86_64", pkgnum:"2_slack14.2")) flag++;

if (slackware_check(osver:"current", pkgname:"glibc", pkgver:"2.25", pkgarch:"i586", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", pkgname:"glibc-i18n", pkgver:"2.25", pkgarch:"i586", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", pkgname:"glibc-profile", pkgver:"2.25", pkgarch:"i586", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", pkgname:"glibc-solibs", pkgver:"2.25", pkgarch:"i586", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"glibc", pkgver:"2.25", pkgarch:"x86_64", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"glibc-i18n", pkgver:"2.25", pkgarch:"x86_64", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"glibc-profile", pkgver:"2.25", pkgarch:"x86_64", pkgnum:"3")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"glibc-solibs", pkgver:"2.25", pkgarch:"x86_64", pkgnum:"3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

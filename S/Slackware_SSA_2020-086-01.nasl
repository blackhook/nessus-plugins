#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2020-086-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(134971);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/31");

  script_cve_id("CVE-2018-21008", "CVE-2019-11487", "CVE-2019-14615", "CVE-2019-14895", "CVE-2019-14896", "CVE-2019-14897", "CVE-2019-14901", "CVE-2019-15217", "CVE-2019-15220", "CVE-2019-15221", "CVE-2019-16233", "CVE-2019-16234", "CVE-2019-19056", "CVE-2019-19066", "CVE-2019-19068", "CVE-2019-19965", "CVE-2019-5108", "CVE-2020-0009", "CVE-2020-2732", "CVE-2020-8647", "CVE-2020-8648", "CVE-2020-8649", "CVE-2020-9383");
  script_xref(name:"SSA", value:"2020-086-01");

  script_name(english:"Slackware 14.2 : Slackware 14.2 kernel (SSA:2020-086-01)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New kernel packages are available for Slackware 14.2 to fix security
issues."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2020&m=slackware-security.760705
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a55cd09d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-generic-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-huge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-huge-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-modules-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (slackware_check(osver:"14.2", pkgname:"kernel-generic", pkgver:"4.4.217", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", pkgname:"kernel-generic-smp", pkgver:"4.4.217_smp", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", pkgname:"kernel-headers", pkgver:"4.4.217_smp", pkgarch:"x86", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", pkgname:"kernel-huge", pkgver:"4.4.217", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", pkgname:"kernel-huge-smp", pkgver:"4.4.217_smp", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", pkgname:"kernel-modules", pkgver:"4.4.217", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", pkgname:"kernel-modules-smp", pkgver:"4.4.217_smp", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", pkgname:"kernel-source", pkgver:"4.4.217_smp", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"kernel-generic", pkgver:"4.4.217", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"kernel-headers", pkgver:"4.4.217", pkgarch:"x86", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"kernel-huge", pkgver:"4.4.217", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"kernel-modules", pkgver:"4.4.217", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"kernel-source", pkgver:"4.4.217", pkgarch:"noarch", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

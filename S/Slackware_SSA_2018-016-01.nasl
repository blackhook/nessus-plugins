#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2018-016-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106051);
  script_version("3.5");
  script_cvs_date("Date: 2019/04/05 23:25:07");

  script_cve_id("CVE-2017-5715", "CVE-2017-5754");
  script_xref(name:"SSA", value:"2018-016-01");
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"Slackware 14.0 / 14.2 / current : kernel (SSA:2018-016-01) (Meltdown) (Spectre)");
  script_summary(english:"Checks for updated packages in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New kernel packages are available for Slackware 14.0 and 14.2 to fix
security issues."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2018&m=slackware-security.1191628
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1935a7d1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-generic-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-huge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-huge-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-modules-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (slackware_check(osver:"14.0", pkgname:"kernel-firmware", pkgver:"20180104_65b1c68", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", pkgname:"kernel-generic", pkgver:"3.2.98", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", pkgname:"kernel-generic-smp", pkgver:"3.2.98_smp", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", pkgname:"kernel-headers", pkgver:"3.2.98_smp", pkgarch:"x86", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", pkgname:"kernel-huge", pkgver:"3.2.98", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", pkgname:"kernel-huge-smp", pkgver:"3.2.98_smp", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", pkgname:"kernel-modules", pkgver:"3.2.98", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", pkgname:"kernel-modules-smp", pkgver:"3.2.98_smp", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", pkgname:"kernel-source", pkgver:"3.2.98_smp", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"kernel-firmware", pkgver:"20180104_65b1c68", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"kernel-generic", pkgver:"3.2.98", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"kernel-headers", pkgver:"3.2.98", pkgarch:"x86", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"kernel-huge", pkgver:"3.2.98", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"kernel-modules", pkgver:"3.2.98", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"kernel-source", pkgver:"3.2.98", pkgarch:"noarch", pkgnum:"1")) flag++;

if (slackware_check(osver:"14.2", pkgname:"kernel-firmware", pkgver:"20180104_65b1c68", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", pkgname:"kernel-generic", pkgver:"4.4.111", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", pkgname:"kernel-generic-smp", pkgver:"4.4.111_smp", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", pkgname:"kernel-headers", pkgver:"4.4.111_smp", pkgarch:"x86", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", pkgname:"kernel-huge", pkgver:"4.4.111", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", pkgname:"kernel-huge-smp", pkgver:"4.4.111_smp", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", pkgname:"kernel-modules", pkgver:"4.4.111", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", pkgname:"kernel-modules-smp", pkgver:"4.4.111_smp", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", pkgname:"kernel-source", pkgver:"4.4.111_smp", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"kernel-firmware", pkgver:"20180104_65b1c68", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"kernel-generic", pkgver:"4.4.111", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"kernel-headers", pkgver:"4.4.111", pkgarch:"x86", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"kernel-huge", pkgver:"4.4.111", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"kernel-modules", pkgver:"4.4.111", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"kernel-source", pkgver:"4.4.111", pkgarch:"noarch", pkgnum:"1")) flag++;

if (slackware_check(osver:"current", pkgname:"kernel-firmware", pkgver:"20180104_65b1c68", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-generic", pkgver:"4.14.13", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-generic-smp", pkgver:"4.14.13_smp", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-headers", pkgver:"4.14.13_smp", pkgarch:"x86", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-huge", pkgver:"4.14.13", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-huge-smp", pkgver:"4.14.13_smp", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-modules", pkgver:"4.14.13", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-modules-smp", pkgver:"4.14.13_smp", pkgarch:"i686", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"kernel-source", pkgver:"4.14.13_smp", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"kernel-firmware", pkgver:"20180104_65b1c68", pkgarch:"noarch", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"kernel-generic", pkgver:"4.14.13", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"kernel-headers", pkgver:"4.14.13", pkgarch:"x86", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"kernel-huge", pkgver:"4.14.13", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"kernel-modules", pkgver:"4.14.13", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"kernel-source", pkgver:"4.14.13", pkgarch:"noarch", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2006-178-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21765);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2006-2449");
  script_xref(name:"SSA", value:"2006-178-01");

  script_name(english:"Slackware 10.0 / 10.1 / 10.2 / current : kdebase kdm local file reading vulnerability (SSA:2006-178-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New kdebase packages are available for Slackware 10.0, 10.1, 10.2,
and -current to fix a security issue with KDM (the KDE login manager)
which could be exploited by a local attacker to read any file on the
system. The official KDE security advisory may be found here:
http://www.kde.org/info/security/advisory-20060614-1.txt"
  );
  # http://www.kde.org/info/security/advisory-20060614-1.txt
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.kde.org/info/security/advisory-20060614-1.txt"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.444467
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4615d4d6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdebase package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (slackware_check(osver:"10.0", pkgname:"kdebase", pkgver:"3.2.3", pkgarch:"i486", pkgnum:"4_slack10.0")) flag++;

if (slackware_check(osver:"10.1", pkgname:"kdebase", pkgver:"3.3.2", pkgarch:"i486", pkgnum:"3_slack10.1")) flag++;

if (slackware_check(osver:"10.2", pkgname:"kdebase", pkgver:"3.4.2", pkgarch:"i486", pkgnum:"3_slack10.2")) flag++;

if (slackware_check(osver:"current", pkgname:"kdebase", pkgver:"3.5.3", pkgarch:"i486", pkgnum:"2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2004-124-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(18768);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2004-0426");
  script_xref(name:"SSA", value:"2004-124-01");

  script_name(english:"Slackware 8.1 / 9.0 / 9.1 / current : rsync update (SSA:2004-124-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New rsync packages are available for Slackware 8.1, 9.0, 9.1, and
-current to fix a security issue. When running an rsync server without
the chroot option it is possible for an attacker to write outside of
the allowed directory. Any sites running rsync in that mode should
upgrade right away (and should probably look into using the chroot
option as well)."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2004&m=slackware-security.403462
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b9e9da7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected rsync package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:rsync");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"8.1", pkgname:"rsync", pkgver:"2.6.2", pkgarch:"i386", pkgnum:"1")) flag++;

if (slackware_check(osver:"9.0", pkgname:"rsync", pkgver:"2.6.2", pkgarch:"i386", pkgnum:"1")) flag++;

if (slackware_check(osver:"9.1", pkgname:"rsync", pkgver:"2.6.2", pkgarch:"i486", pkgnum:"1")) flag++;

if (slackware_check(osver:"current", pkgname:"rsync", pkgver:"2.6.2", pkgarch:"i486", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

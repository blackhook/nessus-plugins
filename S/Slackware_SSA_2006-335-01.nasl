#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2006-335-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24659);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2006-6097");
  script_xref(name:"SSA", value:"2006-335-01");

  script_name(english:"Slackware 10.0 / 10.1 / 10.2 / 11.0 / 8.1 / 9.0 / 9.1 : tar (SSA:2006-335-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New tar packages are available for Slackware 8.1, 9.0, 9.1, 10.0,
10.1, 10.2, and 11.0 to fix a security issue."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.469379
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82740921"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tar package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:tar");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/21");
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
if (slackware_check(osver:"8.1", pkgname:"tar", pkgver:"1.16", pkgarch:"i386", pkgnum:"1_slack8.1")) flag++;

if (slackware_check(osver:"9.0", pkgname:"tar", pkgver:"1.16", pkgarch:"i386", pkgnum:"1_slack9.0")) flag++;

if (slackware_check(osver:"9.1", pkgname:"tar", pkgver:"1.16", pkgarch:"i486", pkgnum:"1_slack9.1")) flag++;

if (slackware_check(osver:"10.0", pkgname:"tar", pkgver:"1.16", pkgarch:"i486", pkgnum:"1_slack10.0")) flag++;

if (slackware_check(osver:"10.1", pkgname:"tar", pkgver:"1.16", pkgarch:"i486", pkgnum:"1_slack10.1")) flag++;

if (slackware_check(osver:"10.2", pkgname:"tar", pkgver:"1.16", pkgarch:"i486", pkgnum:"1_slack10.2")) flag++;

if (slackware_check(osver:"11.0", pkgname:"tar", pkgver:"1.16", pkgarch:"i486", pkgnum:"1_slack11.0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

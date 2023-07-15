#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2017-279-02. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103704);
  script_version("3.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-9572", "CVE-2016-9573", "CVE-2016-9580", "CVE-2016-9581", "CVE-2017-12982", "CVE-2017-14039", "CVE-2017-14040", "CVE-2017-14041", "CVE-2017-14151", "CVE-2017-14152", "CVE-2017-14164");
  script_xref(name:"SSA", value:"2017-279-02");

  script_name(english:"Slackware 14.2 / current : openjpeg (SSA:2017-279-02)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New openjpeg packages are available for Slackware 14.2 and -current
to fix security issues."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2017&m=slackware-security.395569
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?afbd26c3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openjpeg package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:openjpeg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"14.2", pkgname:"openjpeg", pkgver:"2.3.0", pkgarch:"i586", pkgnum:"1_slack14.2")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"openjpeg", pkgver:"2.3.0", pkgarch:"x86_64", pkgnum:"1_slack14.2")) flag++;

if (slackware_check(osver:"current", pkgname:"openjpeg", pkgver:"2.3.0", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"openjpeg", pkgver:"2.3.0", pkgarch:"x86_64", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2013-135-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66449);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_bugtraq_id(53803, 59855, 59858, 59859, 59860, 59861, 59862, 59863, 59864, 59865, 59868, 59869, 59870, 59872, 59873);
  script_xref(name:"SSA", value:"2013-135-01");

  script_name(english:"Slackware 13.37 / 14.0 / current : mozilla-firefox (SSA:2013-135-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New mozilla-firefox packages are available for Slackware 13.37, 14.0,
and -current to fix security issues."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2013&m=slackware-security.398798
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?620f85b5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mozilla-firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.37");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"13.37", pkgname:"mozilla-firefox", pkgver:"17.0.6esr", pkgarch:"i486", pkgnum:"1_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"mozilla-firefox", pkgver:"17.0.6esr", pkgarch:"x86_64", pkgnum:"1_slack13.37")) flag++;

if (slackware_check(osver:"14.0", pkgname:"mozilla-firefox", pkgver:"21.0", pkgarch:"i486", pkgnum:"1_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"mozilla-firefox", pkgver:"21.0", pkgarch:"x86_64", pkgnum:"1_slack14.0")) flag++;

if (slackware_check(osver:"current", pkgname:"mozilla-firefox", pkgver:"21.0", pkgarch:"i486", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"mozilla-firefox", pkgver:"21.0", pkgarch:"x86_64", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

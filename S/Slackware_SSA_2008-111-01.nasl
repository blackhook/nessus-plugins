#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2008-111-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(32033);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-1686");
  script_bugtraq_id(28665);
  script_xref(name:"SSA", value:"2008-111-01");

  script_name(english:"Slackware 10.0 / 10.1 / 10.2 / 11.0 / 12.0 / current : xine-lib (SSA:2008-111-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New xine-lib packages are available for Slackware 10.0, 10.1, 10.2,
11.0, 12.0, and -current to fix security issues. An overflow was found
in the Speex decoder that could lead to a crash or possible execution
of arbitrary code. Xine-lib <= 1.1.12 was also found to be vulnerable
to a stack-based buffer overflow in the NES demuxer (thanks to
milw0rm.com)."
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2008&m=slackware-security.460836
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ac852785"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xine-lib package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:xine-lib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 Tenable Network Security, Inc.");
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
if (slackware_check(osver:"10.0", pkgname:"xine-lib", pkgver:"1.1.11.1", pkgarch:"i686", pkgnum:"3_slack10.0")) flag++;

if (slackware_check(osver:"10.1", pkgname:"xine-lib", pkgver:"1.1.11.1", pkgarch:"i686", pkgnum:"3_slack10.1")) flag++;

if (slackware_check(osver:"10.2", pkgname:"xine-lib", pkgver:"1.1.11.1", pkgarch:"i686", pkgnum:"3_slack10.2")) flag++;

if (slackware_check(osver:"11.0", pkgname:"xine-lib", pkgver:"1.1.11.1", pkgarch:"i686", pkgnum:"3_slack11.0")) flag++;

if (slackware_check(osver:"12.0", pkgname:"xine-lib", pkgver:"1.1.11.1", pkgarch:"i686", pkgnum:"3_slack12.0")) flag++;

if (slackware_check(osver:"current", pkgname:"xine-lib", pkgver:"1.1.11.1", pkgarch:"i686", pkgnum:"3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

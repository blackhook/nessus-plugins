#%NASL_MIN_LEVEL 999999

# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a security fix.
#
# Disabled on 2012/09/06.
#

#
# (C) Tenable Network Security, Inc.
#
# This script was automatically generated from
# Mandrake Linux Security Advisory MDKA-2006:019.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(24503);
  script_version ("1.11");
  script_cvs_date("Date: 2018/07/20  0:18:52");

  script_name(english:"MDKA-2006:019 : postgresql");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandrake host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"Various bugs in the PostgreSQL 8.0.x branch have been corrected with
the latest 8.0.7 maintenance release which is being provided for
Mandriva Linux 2006 users.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDKA-2006:019");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/14");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/18");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2007-2018 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a security fix.");


include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Mandrake/release")) exit(0, "The host is not running Mandrake Linux.");
if (!get_kb_item("Host/Mandrake/rpm-list")) exit(1, "Could not get the list of packages.");

flag = 0;

if (rpm_check(reference:"libecpg5-8.0.7-0.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libecpg5-devel-8.0.7-0.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libpq4-8.0.7-0.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libpq4-devel-8.0.7-0.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"postgresql-8.0.7-0.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"postgresql-contrib-8.0.7-0.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"postgresql-devel-8.0.7-0.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"postgresql-docs-8.0.7-0.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"postgresql-jdbc-8.0.7-0.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"postgresql-pl-8.0.7-0.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"postgresql-plperl-8.0.7-0.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"postgresql-plpgsql-8.0.7-0.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"postgresql-plpython-8.0.7-0.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"postgresql-pltcl-8.0.7-0.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"postgresql-server-8.0.7-0.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"postgresql-test-8.0.7-0.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else 
{
  exit(0, "The host is not affected.");
}

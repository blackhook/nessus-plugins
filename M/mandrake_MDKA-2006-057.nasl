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
# Mandrake Linux Security Advisory MDKA-2006:057.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(24532);
  script_version ("1.11");
  script_cvs_date("Date: 2018/07/20  0:18:52");

  script_name(english:"MDKA-2006:057 : clamav");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandrake host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"There are no known security issues with clamav-0.88.5, which was
included in the last update (MDKSA-2006:184). Upstream has released a
new stable 0.88.6, with some bugfixes. This update is to address user
reports with regards to clamav's behavior of producing output such
as:

WARNING: Your ClamAV installation is OUTDATED! WARNING: Current
functionality level = 9, recommended = 10 DON'T PANIC! Read
http://www.clamav.net/faq.html

If one is not running the latest release.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDKA-2006:057");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/01");
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

if (rpm_check(reference:"clamav-0.88.6-0.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"clamav-db-0.88.6-0.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"clamav-milter-0.88.6-0.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"clamd-0.88.6-0.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libclamav1-0.88.6-0.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libclamav1-devel-0.88.6-0.1.20060mdk", release:"MDK2006.0", cpu:"i386", yank:"mdk")) flag++;

if (rpm_check(reference:"clamav-0.88.6-0.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"clamav-db-0.88.6-0.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"clamav-milter-0.88.6-0.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"clamd-0.88.6-0.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"lib64clamav1-0.88.6-0.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"lib64clamav1-devel-0.88.6-0.1.20060mdk", release:"MDK2006.0", cpu:"x86_64", yank:"mdk")) flag++;

if (rpm_check(reference:"clamav-0.88.6-1.1mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"clamav-db-0.88.6-1.1mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"clamav-milter-0.88.6-1.1mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"clamd-0.88.6-1.1mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libclamav1-0.88.6-1.1mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libclamav1-devel-0.88.6-1.1mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"clamav-0.88.6-1.1mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"clamav-db-0.88.6-1.1mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"clamav-milter-0.88.6-1.1mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"clamd-0.88.6-1.1mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64clamav1-0.88.6-1.1mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64clamav1-devel-0.88.6-1.1mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;


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

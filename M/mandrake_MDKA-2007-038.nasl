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
# Mandrake Linux Security Advisory MDKA-2007:038.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(36401);
  script_version ("1.9");
  script_cvs_date("Date: 2018/07/20  0:18:52");

  script_name(english:"MDKA-2007:038 : mandriva-theme");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandrake host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"Some background images were not consistent with the final 2007 Spring
theme. This update package fixes the Mandriva-1440x900 and
Mandriva-Powerpack+-1280x800 background images.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDKA-2007:038");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/23");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2009-2018 Tenable Network Security, Inc.");

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

if (rpm_check(reference:"mandriva-theme-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-Discovery-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-Discovery-screensaver-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-Flash-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-Flash-screensaver-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-One-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-One-screensaver-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-Powerpack+-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-Powerpack+-screensaver-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-Powerpack-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-Powerpack-screensaver-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-common-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-screensaver-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-Discovery-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-Discovery-screensaver-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-Flash-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-Flash-screensaver-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-One-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-One-screensaver-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-Powerpack+-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-Powerpack+-screensaver-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-Powerpack-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-Powerpack-screensaver-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-common-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;
if (rpm_check(reference:"mandriva-theme-screensaver-1.2.11-1.2mdv2007.1", release:"MDK2007.1", cpu:"noarch", yank:"mdv")) flag++;


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
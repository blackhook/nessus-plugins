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
# Mandrake Linux Security Advisory MDKA-2007:060.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(37896);
  script_version ("1.9");
  script_cvs_date("Date: 2018/07/20  0:18:52");

  script_name(english:"MDKA-2007:060 : gnome-vfs2");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandrake host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"Unionfs filesystems were not being recognized as supporting trash for
GNOME applications. This was preventing the Flash-based product to
have a fully functional trash under the GNOME desktop environment.
This update fixes the bug and improves performance for XFS filesystem
users as well.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDKA-2007:060");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/14");
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

if (rpm_check(reference:"gnome-vfs2-2.18.1-2.1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libgnome-vfs2_0-2.18.1-2.1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libgnome-vfs2_0-devel-2.18.1-2.1mdv2007.1", release:"MDK2007.1", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"gnome-vfs2-2.18.1-2.1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64gnome-vfs2_0-2.18.1-2.1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64gnome-vfs2_0-devel-2.18.1-2.1mdv2007.1", release:"MDK2007.1", cpu:"x86_64", yank:"mdv")) flag++;


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

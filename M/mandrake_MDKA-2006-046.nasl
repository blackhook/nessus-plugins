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
# Mandrake Linux Security Advisory MDKA-2006:046.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(24521);
  script_version ("1.11");
  script_cvs_date("Date: 2018/07/20  0:18:52");

  script_name(english:"MDKA-2006:046 : bootsplash");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandrake host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"When multiple profiles are configured, they can be choosen in the
bootloader with the PROFILE keyword, but this needs a dedicated entry
or to append manually the profile at each boot. To ease the choice of
the profile during the boot time, Mandriva developed a frame buffer
menu in GTK to choose the profile.

Unfortunately in 2007, a miscompilation removed this application from
the bootsplash package, thus the only left method to choose a profile
was the bootloader one. This new package of bootsplash brings back
the 'fbmenu' command which display the appropriate profile selection
menu during boot.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDKA-2006:046");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/24");
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

if (rpm_check(reference:"bootsplash-3.1.14-1.1mdv2007.0", release:"MDK2007.0", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"bootsplash-3.1.14-1.1mdv2007.0", release:"MDK2007.0", cpu:"x86_64", yank:"mdv")) flag++;


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

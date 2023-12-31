#%NASL_MIN_LEVEL 70300

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
# Mandriva Linux Security Advisory MDVA-2009:107.
#

if (!defined_func("bn_random")) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(39385);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_name(english:"MDVA-2009:107 : udev");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"udev network hotplug scripts before this update doesn't ignore
tmpbridge interface, created by xen network-bridge script. This makes
bridged xen network setup to fail. The update addresses the issue,
making network hotplug ignore tmpbridge interface. Affects only xen
users using bridges for network setup.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2009:107");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/12");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/06/15");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2009-2021 Tenable Network Security, Inc.");

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

if (rpm_check(reference:"libudev0-128-2.4mnb2", release:"MDK2009.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libudev0-devel-128-2.4mnb2", release:"MDK2009.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libvolume_id1-128-2.4mnb2", release:"MDK2009.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libvolume_id1-devel-128-2.4mnb2", release:"MDK2009.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"udev-128-2.4mnb2", release:"MDK2009.0", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"udev-doc-128-2.4mnb2", release:"MDK2009.0", cpu:"i386", yank:"mdk")) flag++;

if (rpm_check(reference:"lib64udev0-128-2.4mnb2", release:"MDK2009.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"lib64udev0-devel-128-2.4mnb2", release:"MDK2009.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"lib64volume_id1-128-2.4mnb2", release:"MDK2009.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"lib64volume_id1-devel-128-2.4mnb2", release:"MDK2009.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"udev-128-2.4mnb2", release:"MDK2009.0", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"udev-doc-128-2.4mnb2", release:"MDK2009.0", cpu:"x86_64", yank:"mdk")) flag++;

if (rpm_check(reference:"libudev0-140-3.2mnb2", release:"MDK2009.1", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libudev0-devel-140-3.2mnb2", release:"MDK2009.1", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libvolume_id1-140-3.2mnb2", release:"MDK2009.1", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libvolume_id1-devel-140-3.2mnb2", release:"MDK2009.1", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"udev-140-3.2mnb2", release:"MDK2009.1", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"udev-doc-140-3.2mnb2", release:"MDK2009.1", cpu:"i386", yank:"mdk")) flag++;

if (rpm_check(reference:"lib64udev0-140-3.2mnb2", release:"MDK2009.1", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"lib64udev0-devel-140-3.2mnb2", release:"MDK2009.1", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"lib64volume_id1-140-3.2mnb2", release:"MDK2009.1", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"lib64volume_id1-devel-140-3.2mnb2", release:"MDK2009.1", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"udev-140-3.2mnb2", release:"MDK2009.1", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"udev-doc-140-3.2mnb2", release:"MDK2009.1", cpu:"x86_64", yank:"mdk")) flag++;


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

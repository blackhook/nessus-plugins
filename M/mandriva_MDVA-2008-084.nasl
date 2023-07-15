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
# Mandriva Linux Security Advisory MDVA-2008:084.
#

if (!defined_func("bn_random")) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(36511);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_name(english:"MDVA-2008:084 : udev");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"The udev rules for network interfaces used to write persistent
settings for hso devices in /etc/udev/rules.d/61-net_config.rules,
which is wrong since their MAC address is random (#39977).

The udev rules for automatic driver loading used to load video
drivers during the dkms service start, which could break Xorg start
if the loaded driver was not configured.

This update fixes both issues.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2008:084");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/03");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/23");
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

if (rpm_check(reference:"libvolume_id0-118-6.2mnb1", release:"MDK2008.1", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libvolume_id0-devel-118-6.2mnb1", release:"MDK2008.1", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"udev-118-6.2mnb1", release:"MDK2008.1", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"udev-doc-118-6.2mnb1", release:"MDK2008.1", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"udev-tools-118-6.2mnb1", release:"MDK2008.1", cpu:"i386", yank:"mdk")) flag++;

if (rpm_check(reference:"lib64volume_id0-118-6.2mnb1", release:"MDK2008.1", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"lib64volume_id0-devel-118-6.2mnb1", release:"MDK2008.1", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"udev-118-6.2mnb1", release:"MDK2008.1", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"udev-doc-118-6.2mnb1", release:"MDK2008.1", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"udev-tools-118-6.2mnb1", release:"MDK2008.1", cpu:"x86_64", yank:"mdk")) flag++;


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
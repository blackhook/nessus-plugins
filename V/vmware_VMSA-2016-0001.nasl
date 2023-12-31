#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2016-0001. 
# The text itself is copyright (C) VMware Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87889);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2015-6933");
  script_xref(name:"VMSA", value:"2016-0001");

  script_name(english:"VMSA-2016-0001 : VMware ESXi, Workstation, Player, and Fusion updates address important guest privilege escalation vulnerability");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESXi host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Important Windows-based guest privilege escalation in VMware Tools

A kernel memory corruption vulnerability is present in the VMware Tools
'Shared Folders' (HGFS) feature running on Microsoft Windows. Successful
exploitation of this issue could lead to an escalation of privilege in
the guest operating system.

VMware would like to thank Dmitry Janushkevich from the Secunia
Research Team for reporting this issue to us.

Note: This vulnerability does not allow for privilege escalation from
the guest operating system to the host. Host memory can not be
manipulated from the guest operating system by exploiting this flaw.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifier CVE-2015-6933 to this issue.

Workarounds
Removing the 'Shared Folders' (HGFS) feature from previously installed
VMware Tools will remove the possibility of exploitation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2016/000316.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"VMware ESX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/VMware/release", "Host/VMware/version");
  script_require_ports("Host/VMware/esxupdate", "Host/VMware/esxcli_software_vibs");

  exit(0);
}


include("audit.inc");
include("vmware_esx_packages.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/VMware/release")) audit(AUDIT_OS_NOT, "VMware ESX / ESXi");
if (
  !get_kb_item("Host/VMware/esxcli_software_vibs") &&
  !get_kb_item("Host/VMware/esxupdate")
) audit(AUDIT_PACKAGE_LIST_MISSING);


init_esx_check(date:"2016-01-07");
flag = 0;


if (esx_check(ver:"ESXi 5.0", vib:"VMware:tools-light:5.0.0-3.70.3088986")) flag++;

if (esx_check(ver:"ESXi 5.1", vib:"VMware:tools-light:5.1.0-3.57.3021178")) flag++;

if (esx_check(ver:"ESXi 5.5", vib:"VMware:tools-light:5.5.0-3.75.3247226")) flag++;

if (esx_check(ver:"ESXi 6.0", vib:"VMware:tools-light:6.0.0-1.23.3341439")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:esx_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

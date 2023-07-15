#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2016-0023. 
# The text itself is copyright (C) VMware Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(96084);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2016-7463");
  script_xref(name:"VMSA", value:"2016-0023");

  script_name(english:"VMSA-2016-0023 : VMware ESXi updates address a cross-site scripting issue");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESXi host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. Host Client stored cross-site scripting issue

The ESXi Host Client contains a vulnerability that may allow for
stored cross-site scripting (XSS). The issue can be introduced by
an attacker that has permission to manage virtual machines through
ESXi Host Client or by tricking the vSphere administrator to import
a specially crafted VM. The issue may be triggered on the system
from where ESXi Host Client is used to manage the specially crafted
VM.

VMware advises not to import VMs from untrusted sources.

VMware would like to thank Caleb Watt (@calebwatt15) for reporting
this issue to us.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifier CVE-2016-7463 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2016/000361.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/22");
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


init_esx_check(date:"2016-12-20");
flag = 0;


if (esx_check(ver:"ESXi 5.5", vib:"VMware:esx-ui:1.12.0-4722375")) flag++;

if (esx_check(ver:"ESXi 6.0", vib:"VMware:esx-ui:1.9.0-4392584")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:esx_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

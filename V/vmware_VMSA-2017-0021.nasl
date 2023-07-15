#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2017-0021. 
# The text itself is copyright (C) VMware Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105410);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-4933", "CVE-2017-4940", "CVE-2017-4941", "CVE-2017-4943");
  script_xref(name:"VMSA", value:"2017-0021");

  script_name(english:"VMSA-2017-0021 : VMware ESXi, vCenter Server Appliance, Workstation and Fusion updates address multiple security vulnerabilities");
  script_summary(english:"Checks esxupdate output for the patches");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote VMware ESXi host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. ESXi, Workstation, and Fusion stack overflow via authenticated
VNC session

VMware ESXi, Workstation, and Fusion contain a vulnerability that
could allow an authenticated VNC session to cause a stack overflow
via a specific set of VNC packets. Successful exploitation of this
issue could result in remote code execution in a virtual machine via
the authenticated VNC session.

Note: In order for exploitation to be possible in ESXi, VNC must be
manually enabled in a virtual machine's .vmx configuration file. In
addition, ESXi must be configured to allow VNC traffic through the
built-in firewall.

VMware would like to thank Lilith Wyatt and another member of Cisco
Talos for reporting this issue to us.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifier CVE-2017-4941 to this issue.

b. ESXi, Workstation, and Fusion heap overflow via authenticated
VNC session

VMware ESXi, Workstation, and Fusion contain a vulnerability that
could allow an authenticated VNC session to cause a heap overflow
via a specific set of VNC packets resulting in heap corruption.
Successful exploitation of this issue could result in remote code
execution in a virtual machine via the authenticated VNC session.

Note: In order for exploitation to be possible in ESXi, VNC must be
manually enabled in a virtual machine's .vmx configuration file. In
addition, ESXi must be configured to allow VNC traffic through the
built-in firewall.

VMware would like to thank Lilith Wyatt of Cisco Talos for reporting
this issue to us.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifier CVE-2017-4933 to this issue.

c. ESXi Host Client stored cross-site scripting vulnerability

The ESXi Host Client contains a vulnerability that may allow for
stored cross-site scripting (XSS). An attacker can exploit this
vulnerability by injecting Javascript, which might get executed
when other users access the Host Client.

VMware would like to thank Alain Homewood of Insomnia Security
for reporting this issue to us.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifier CVE-2017-4940 to this issue.
d. Privilege escalation in vCenter Server Appliance (vCSA)

VMware vCenter Server Appliance (vCSA) contains a local privilege
escalation vulnerability via the 'showlog' plugin. Successful
exploitation of this issue could result in a low privileged user
gaining root level privileges over the appliance base OS.

VMware would like to thank Lukasz Plonka for reporting this issue
to us.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifier CVE-2017-4943 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2017/000394.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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


init_esx_check(date:"2017-12-19");
flag = 0;


if (esx_check(ver:"ESXi 5.5", vib:"VMware:esx-base:5.5.0-3.103.6480267")) flag++;
if (esx_check(ver:"ESXi 5.5", vib:"VMware:esx-ui:1.12.0-6027315")) flag++;

if (esx_check(ver:"ESXi 6.0", vib:"VMware:esx-base:6.0.0-3.76.6856897")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:esx-ui:1.22.0-6282878")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:vsan:6.0.0-3.76.6769077")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:vsanhealth:6.0.0-3000000.3.0.3.76.6769078")) flag++;

if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-base:6.5.0-1.29.6765664")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-tboot:6.5.0-1.29.6765664")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-ui:1.23.0-6506686")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsan:6.5.0-1.29.6765666")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsanhealth:6.5.0-1.29.6765667")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2016-0014. 
# The text itself is copyright (C) VMware Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93512);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2016-7079", "CVE-2016-7080", "CVE-2016-7081", "CVE-2016-7082", "CVE-2016-7083", "CVE-2016-7084", "CVE-2016-7085", "CVE-2016-7086");
  script_xref(name:"VMSA", value:"2016-0014");

  script_name(english:"VMSA-2016-0014 : VMware ESXi, Workstation, Fusion, &amp; Tools updates address multiple security issues");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESXi host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. VMware Workstation heap-based buffer overflow vulnerabilities via
   Cortado ThinPrint

VMware Workstation contains vulnerabilities that may allow a windows
-based virtual machine (VM) to trigger heap-based buffer overflows
in the windows-based hypervisor running VMware workstation that the
VM resides on. Exploitation of this issue may lead to arbitrary code
execution in the hypervisor OS.

Exploitation is only possible if virtual printing has been enabled
in VMware Workstation. This feature is not enabled by default.
VMware Knowledge Base article 2146810 documents the procedure for
enabling and disabling this feature.

VMware would like to thank E0DB6391795D7F629B5077842E649393 working
with Trend Micro's Zero Day Initiative for reporting this issue to
us.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifier CVE-2016-7081 to this issue.

b. VMware Workstation memory corruption vulnerabilities via Cortado
   Thinprint

VMware Workstation contains vulnerabilities that may allow a windows
-based virtual machine (VM) to corrupt memory in the windows-based
hypervisor running VMware workstation that the VM resides on. These
include TrueType fonts embedded in EMFSPOOL (CVE-2016-7083), and
JPEG2000 images (CVE-2016-7084) in tpview.dll. Exploitation of these
issues may lead to arbitrary code execution in the hypervisor OS.

Exploitation is only possible if virtual printing has been enabled
in VMware Workstation. This feature is not enabled by default.
VMware Knowledge Base article 2146810 documents the procedure for
enabling and disabling this feature.

VMware would like to thank Mateusz Jurczyk of Google's Project Zero
for reporting these issues to us.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifiers CVE-2016-7083, and CVE-2016-7084 to these
issues.

c. VMware Tools NULL pointer dereference vulnerabilities

The graphic acceleration functions used in VMware Tools for OSX
handle memory incorrectly. Two resulting NULL pointer dereference
vulnerabilities may allow for local privilege escalation on Virtual
Machines that run OSX.

The issues can be remediated by installing a fixed version of VMware
Tools on affected OSX VMs directly. Alternatively the fixed version
of Tools can be installed through ESXi or Fusion after first
updating to a version of ESXi or Fusion that ships with a fixed
version of VMware Tools.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifiers CVE-2016-7079 and CVE-2016-7080 to these
issues.

VMware would like to thank Dr. Fabien Duchene 'FuzzDragon' and Jian
Zhu for independently reporting these issues to VMware.

d. VMware Workstation installer DLL hijacking issue

Workstation Pro/Player installer contains a DLL hijacking issue that
exists due to some DLL files loaded by the application improperly.
This issue may allow an unauthenticated remote attacker to load this
DLL file of the attacker's choosing that could execute arbitrary
code.

e. VMware Workstation installer insecure executable loading
   vulnerability

Workstation installer contains an insecure executable loading
vulnerability that may allow an attacker to execute any exe file
placed in the same directory as installer with the name
'setup64.exe'.Successfully exploiting this issue may allow attackers
to escalate their privileges and execute arbitrary code.

VMware would like to thank Adam Bridge for reporting this issue to
us.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifier CVE-2016-7086 to this issue.

f. Workstation EMF file handling memory corruption vulnerability via
Cortado ThinPrint

VMware Workstation contains a vulnerability that may allow a Windows
-based virtual machine (VM) to corrupt memory. This issue occurs due
to improper handling of EMF files in tpview.dll. Exploitation of this
issue may lead to arbitrary code execution in the hypervisor OS.

The severity of this issue has changed to Low from Critical as the
exploitation of the issue requires a custom registry value to be
added on the host machine.

Exploitation is only possible if virtual printing has been enabled
in VMware Workstation. This feature is not enabled by default.
VMware Knowledge Base article 2146810 documents the procedure for
enabling and disabling this feature.

VMware would like to thank Mateusz Jurczyk of Google's Project Zero
and Yakun Zhang of McAfee for individually reporting this issue to us.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifier CVE-2016-7082 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2017/000395.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 Tenable Network Security, Inc.");
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


init_esx_check(date:"2016-09-13");
flag = 0;


if (esx_check(ver:"ESXi 5.5", vib:"VMware:tools-light:5.5.0-3.86.4179631")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

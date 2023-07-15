#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2020-0015. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(137826);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/06");

  script_cve_id("CVE-2020-3962", "CVE-2020-3963", "CVE-2020-3964", "CVE-2020-3965", "CVE-2020-3966", "CVE-2020-3967", "CVE-2020-3968", "CVE-2020-3969", "CVE-2020-3970", "CVE-2020-3971");
  script_xref(name:"VMSA", value:"2020-0015");
  script_xref(name:"IAVA", value:"2020-A-0265");

  script_name(english:"VMSA-2020-0015 : VMware ESXi, Workstation, and Fusion updates address multiple security vulnerabilities");
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
"a. Use-after-free vulnerability in SVGA device (CVE-2020-3962)

VMware ESXi, Workstation and Fusion contain a Use-after-free
vulnerability in the SVGA device. A malicious actor with local access
to a virtual machine with 3D graphics enabled may be able to exploit
this vulnerability to execute code on the hypervisor from a virtual
machine.

b. Off-by-one heap-overflow vulnerability in SVGA device (CVE-2020-3969)

VMware ESXi, Workstation and Fusion contain an off-by-one
heap-overflow vulnerability in the SVGA device. A malicious actor with
local access to a virtual machine with 3D graphics enabled may be able
to exploit this vulnerability to execute code on the hypervisor from a
virtual machine. Additional conditions beyond the attackers control
must be present for exploitation to be possible.

c. Out-of-bound read issue in Shader Functionality (CVE-2020-3970)

VMware ESXi, Workstation and Fusion contain an out-of-bounds read
vulnerability in the Shader functionality. A malicious actor with
non-administrative local access to a virtual machine with 3D graphics
enabled may be able to exploit this vulnerability to crash the virtual
machines vmx process leading to a partial denial of service condition.

d. Heap-overflow issue in EHCI controller (CVE-2020-3967)

VMware ESXi, Workstation and Fusion contain a heap-overflow
vulnerability in the USB 2.0 controller (EHCI). A malicious actor with
local access to a virtual machine may be able to exploit this
vulnerability to execute code on the hypervisor from a virtual
machine. Additional conditions beyond the attackers control must be
present for exploitation to be possible.

e. Out-of-bounds write vulnerability in xHCI controller (CVE-2020-3968)

VMware ESXi, Workstation and Fusion contain an out-of-bounds write
vulnerability in the USB 3.0 controller (xHCI). A malicious actor with
local administrative privileges on a virtual machine may be able to
exploit this issue to crash the virtual machines vmx process leading
to a denial of service condition or execute code on the hypervisor
from a virtual machine. Additional conditions beyond the attackers
control must be present for exploitation to be possible.

f. Heap-overflow due to race condition in EHCI controller (CVE-2020-3966)

VMware ESXi, Workstation and Fusion contain a heap-overflow due to a
race condition issue in the USB 2.0 controller (EHCI). A malicious
actor with local access to a virtual machine may be able to exploit
this vulnerability to execute code on the hypervisor from a virtual
machine. Additional conditions beyond the attackers control must be
present for exploitation to be possible.

g. Information leak in the XHCI USB controller (CVE-2020-3965)

VMware ESXi, Workstation and Fusion contain an information leak in the
XHCI USB controller. A malicious actor with local access to a virtual
machine may be able to read privileged information contained in
hypervisor memory from a virtual machine.

h. Information Leak in the EHCI USB controller (CVE-2020-3964)
Description

VMware ESXi, Workstation and Fusion contain an information leak in the
EHCI USB controller. A malicious actor with local access to a virtual
machine may be able to read privileged information contained in the
hypervisors memory. Additional conditions beyond the attackers control
need to be present for exploitation to be possible.

i. Use-after-free vulnerability in PVNVRAM (CVE-2020-3963)

VMware ESXi, Workstation and Fusion contain a Use-after-free
vulnerability in PVNVRAM. A malicious actor with local access to a
virtual machine may be able to read privileged information contained
in physical memory.

j. Heap overflow vulnerability in vmxnet3 (CVE-2020-3971)

VMware ESXi, Fusion and Workstation contain a heap overflow
vulnerability in the vmxnet3 virtual network adapter. A malicious
actor with local access to a virtual machine with a vmxnet3 network
adapter present may be able to read privileged information contained
in physical memory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2020/000500.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3968");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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


init_esx_check(date:"2020-06-23");
flag = 0;


if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-base:6.5.0-3.126.16207673")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-tboot:6.5.0-3.126.16207673")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsan:6.5.0-3.126.15965595")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsanhealth:6.5.0-3.126.15965596")) flag++;

if (esx_check(ver:"ESXi 6.7", vib:"VMware:esx-base:6.7.0-3.108.16316930")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:esx-update:6.7.0-3.108.16316930")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:vsan:6.7.0-3.108.16243518")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:vsanhealth:6.7.0-3.108.16243519")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:esx_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

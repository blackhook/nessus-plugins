#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2020-0026. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(143166);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2020-4004", "CVE-2020-4005");
  script_xref(name:"VMSA", value:"2020-0026");
  script_xref(name:"IAVA", value:"2020-A-0544");

  script_name(english:"VMSA-2020-0026 : VMware ESXi, Workstation and Fusion updates address use-after-free and privilege escalation vulnerabilities");
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
"a. Use-after-free vulnerability in XHCI USB controller (CVE-2020-4004)
VMware ESXi contains a use-after-free vulnerability in the XHCI USB
controller. A malicious actor with local administrative privileges on
a virtual machine may exploit this issue to execute code as the
virtual machines VMX process running on the host.

b. VMX elevation-of-privilege vulnerability (CVE-2020-4005)
VMware ESXi contains a privilege-escalation vulnerability that exists
in the way certain system calls are being managed. A malicious actor
with privileges within the VMX process only, may escalate their
privileges on the affected system. Successful exploitation of this
issue is only possible when chained with another vulnerability
(e.g. CVE-2020-4004)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2020/000515.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4005");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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


init_esx_check(date:"2020-11-19");
flag = 0;


if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-base:6.5.0-3.149.17167537")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-tboot:6.5.0-3.149.17167537")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsan:6.5.0-3.149.17127931")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsanhealth:6.5.0-3.149.17127932")) flag++;

if (esx_check(ver:"ESXi 6.7", vib:"VMware:esx-base:6.7.0-3.128.17167699")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:esx-update:6.7.0-3.128.17167699")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:vsan:6.7.0-3.128.17098396")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:vsanhealth:6.7.0-3.128.17098397")) flag++;

if (esx_check(ver:"ESXi 7.0", vib:"VMware:cpu-microcode:7.0.1-0.15.17168206")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:crx:7.0.1-0.15.17168206")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:esx-base:7.0.1-0.15.17168206")) flag++;
if (
  esx_check(
    ver : "ESXi 7.0",
    vib : "VMware:esx-dvfilter-generic-fastpath:7.0.1-0.15.17168206"
  )
) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:esx-ui:1.34.4-0.0.16668064")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:esx-update:7.0.1-0.15.17168206")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:esx-xserver:7.0.1-0.15.17168206")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:gc:7.0.1-0.15.17168206")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:loadesx:7.0.1-0.15.17168206")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:native-misc-drivers:7.0.1-0.15.17168206")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:vdfs:7.0.1-0.15.17168206")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:vsan:7.0.1-0.15.17168206")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:vsanhealth:7.0.1-0.15.17168206")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

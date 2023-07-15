#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2020-0023. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(141757);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/24");

  script_cve_id("CVE-2020-3981", "CVE-2020-3982", "CVE-2020-3992", "CVE-2020-3995");
  script_xref(name:"VMSA", value:"2020-0023");
  script_xref(name:"IAVA", value:"2020-A-0468");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"VMSA-2020-0023 : VMware ESXi, Workstation, Fusion and NSX-T updates address multiple security vulnerabilities");
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
"a. ESXi OpenSLP remote code execution vulnerability (CVE-2020-3992)

OpenSLP as used in ESXi has a use-after-free issue. A malicious actor
residing in the management network who has access to port 427 on an
ESXi machine may be able to trigger a use-after-free in the OpenSLP
service resulting in remote code execution.

c. TOCTOU out-of-bounds read vulnerability (CVE-2020-3981)

VMware ESXi contains an out-of-bounds read vulnerability due to a
time-of-check time-of-use issue in ACPI device. A malicious actor with
administrative access to a virtual machine may be able to exploit this
issue to leak memory from the vmx process.

d. TOCTOU out-of-bounds write vulnerability (CVE-2020-3982)

VMware ESXi contains an out-of-bounds write vulnerability due to a
time-of-check time-of-use issue in ACPI device. A malicious actor with
administrative access to a virtual machine may be able to exploit this
vulnerability to crash the virtual machine's vmx process or corrupt
hypervisors memory heap.

f. VMCI host driver memory leak vulnerability (CVE-2020-3995)

The VMCI host drivers used by VMware hypervisors contain a memory leak
vulnerability. A malicious actor with access to a virtual machine may
be able to trigger a memory leak issue resulting in memory resource
exhaustion on the hypervisor if the attack is sustained for extended
periods of time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2020/000511.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3992");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/21");
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


init_esx_check(date:"2020-10-20");
flag = 0;


if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-base:6.5.0-3.146.17097218")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-tboot:6.5.0-3.143.16901156")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsan:6.5.0-3.146.17067204")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsanhealth:6.5.0-3.146.17067206")) flag++;

if (esx_check(ver:"ESXi 6.7", vib:"VMware:esx-base:6.7.0-3.120.16773714")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:esx-update:6.7.0-3.123.17098360")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:vsan:6.7.0-3.123.17067304")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:vsanhealth:6.7.0-3.123.17067305")) flag++;

if (esx_check(ver:"ESXi 7.0", vib:"VMware:cpu-microcode:7.0.1-0.10.17119627")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:crx:7.0.1-0.10.17119627")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:esx-base:7.0.1-0.10.17119627")) flag++;
if (
  esx_check(
    ver : "ESXi 7.0",
    vib : "VMware:esx-dvfilter-generic-fastpath:7.0.1-0.10.17119627"
  )
) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:esx-ui:1.34.4-0.0.16668064")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:esx-update:7.0.1-0.0.16850804")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:esx-xserver:7.0.1-0.10.17119627")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:gc:7.0.1-0.10.17119627")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:loadesx:7.0.1-0.0.16850804")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:native-misc-drivers:7.0.1-0.10.17119627")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:vdfs:7.0.1-0.10.17119627")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:vsan:7.0.1-0.10.17119627")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:vsanhealth:7.0.1-0.10.17119627")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

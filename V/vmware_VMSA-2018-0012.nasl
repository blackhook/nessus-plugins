#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2018-0012. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(110901);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2018-3639", "CVE-2018-3640");
  script_xref(name:"VMSA", value:"2018-0012");

  script_name(english:"VMSA-2018-0012 : VMware vSphere, Workstation and Fusion updates enable Hypervisor-Assisted Guest Mitigations for Speculative Store Bypass issue (Spectre)");
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
"vCenter Server, ESXi, Workstation, and Fusion update speculative
execution control mechanism for Virtual Machines (VMs). As a result,
a patched Guest Operating System (GOS) can remediate the Speculative
Store bypass issue (CVE-2018-3639) using the Speculative-Store-
Bypass-Disable (SSBD) control bit. This issue may allow for
information disclosure in applications and/or execution runtimes
which rely on managed code security mechanisms. Based on current
evaluations, we do not believe that CVE-2018-3639 could allow for VM
to VM or Hypervisor to VM Information disclosure.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifier CVE-2018-3639 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2018/000417.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/03");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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


init_esx_check(date:"2018-05-21");
flag = 0;


if (esx_check(ver:"ESXi 5.5", vib:"VMware:cpu-microcode:5.5.0-3.117.8934887")) flag++;
if (esx_check(ver:"ESXi 5.5", vib:"VMware:esx-base:5.5.0-3.117.8934887")) flag++;

if (esx_check(ver:"ESXi 6.0", vib:"VMware:cpu-microcode:6.0.0-3.87.8934903")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:esx-base:6.0.0-3.87.8934903")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:vsan:6.0.0-3.87.8155259")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:vsanhealth:6.0.0-3000000.3.0.3.87.8155260")) flag++;

if (esx_check(ver:"ESXi 6.5", vib:"VMware:cpu-microcode:6.5.0-2.54.8935087")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-base:6.5.0-2.54.8935087")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-tboot:6.5.0-2.54.8935087")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsan:6.5.0-2.54.8359236")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsanhealth:6.5.0-2.54.8359237")) flag++;

if (esx_check(ver:"ESXi 6.7", vib:"VMware:cpu-microcode:6.7.0-0.14.8941472")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:esx-base:6.7.0-0.14.8941472")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:vsan:6.7.0-0.14.8941472")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:vsanhealth:6.7.0-0.14.8941472")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:esx_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

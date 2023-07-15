#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2017-0015. 
# The text itself is copyright (C) VMware Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103357);
  script_version("3.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-4924", "CVE-2017-4925", "CVE-2017-4926");
  script_xref(name:"VMSA", value:"2017-0015");

  script_name(english:"VMSA-2017-0015 : VMware ESXi, vCenter Server, Fusion and Workstation updates resolve multiple security vulnerabilities");
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
"a. Out-of-bounds write vulnerability in SVGA

VMware ESXi, Workstation and Fusion contain an out-of-bounds write
vulnerability in SVGA device. This issue may allow a guest to
execute code on the host.

VMware would like to thank Nico Golde and Ralf-Philipp Weinmann of
Comsecuris UG (haftungsbeschraenkt) working with ZDI for reporting
this issue to us.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifier CVE-2017-4924 to this issue.

b. Guest RPC NULL pointer dereference vulnerability

VMware ESXi, Workstation and Fusion contain a NULL pointer dereference
vulnerability. This issue occurs when handling guest RPC requests.
Successful exploitation of this issue may allow attackers with
normal user privileges to crash their VMs.

VMware would like to thank Zhang Haitao for reporting this issue
to us.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifier CVE-2017-4925 to this issue.

c. Stored XSS in H5 Client

vCenter Server H5 Client contains a vulnerability that may allow for
stored cross-site scripting (XSS). An attacker with VC user
privileges can inject malicious java-scripts which will get executed
when other VC users access the page.

VMware would like to thank Thomas Ornetzeder for reporting this
issue to us.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifier CVE-2017-4926 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2017/000387.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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


init_esx_check(date:"2017-09-14");
flag = 0;


if (esx_check(ver:"ESXi 5.5", vib:"VMware:esx-base:5.5.0-3.103.6480267")) flag++;

if (esx_check(ver:"ESXi 6.0", vib:"VMware:esx-base:6.0.0-3.66.5485776")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:vsan:6.0.0-3.66.5277825")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:vsanhealth:6.0.0-3000000.3.0.3.66.5277826")) flag++;

if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-base:6.5.0-0.23.5969300")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsan:6.5.0-0.23.5665309")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsanhealth:6.5.0-0.23.5633214")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

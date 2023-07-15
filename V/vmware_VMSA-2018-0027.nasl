#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2018-0027. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(118955);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/09");

  script_cve_id("CVE-2018-6981", "CVE-2018-6982");
  script_xref(name:"VMSA", value:"2018-0027");

  script_name(english:"VMSA-2018-0027 : VMware ESXi, Workstation, and Fusion updates address uninitialized stack memory usage");
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
"a. vmxnet3 uninitialized stack memory usage

VMware ESXi, Fusion and Workstation contain uninitialized stack
memory usage in the vmxnet3 virtual network adapter. This
issue may allow a guest to execute code on the host. The issue is
present if vmxnet3 is enabled. Non vmxnet3 virtual adapters are not
affected by this issue.

VMware would like to thank the organizers of GeekPwn2018 and security
researcher Zhangyanyu of Chaitin Tech for reporting this issue to us.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has 
assigned the identifier CVE-2018-6981 to this issue.

b. vmxnet3 uninitialized stack memory usage

VMware ESXi, Fusion and Workstation contain uninitialized stack
memory usage in the vmxnet3 virtual network adapter. This issue may
lead to an information leak from host to guest. The issue is present
if vmxnet3 is enabled. Non vmxnet3 virtual adapters are not affected
by this issue.

VMware would like to thank the organizers of GeekPwn2018 and security
researcher Zhangyanyu of Chaitin Tech for reporting this issue to us.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has 
assigned the identifier CVE-2018-6982 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2018/000441.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6981");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/14");
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


init_esx_check(date:"2018-11-09");
flag = 0;


if (esx_check(ver:"ESXi 6.0", vib:"VMware:esx-base:6.0.0-3.110.10719132")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:vsan:6.0.0-3.110.10644234")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:vsanhealth:6.0.0-3000000.3.0.3.110.10644236")) flag++;

if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-base:6.5.0-2.67.10719125")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-tboot:6.5.0-2.67.10719125")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsan:6.5.0-2.67.10642690")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsanhealth:6.5.0-2.67.10642691")) flag++;

if (esx_check(ver:"ESXi 6.7", vib:"VMware:esx-base:6.7.0-1.31.10764712")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:esx-update:6.7.0-1.31.10764712")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:vsan:6.7.0-1.31.10720746")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:vsanhealth:6.7.0-1.31.10720754")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

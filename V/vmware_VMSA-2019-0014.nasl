#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2019-0014. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(129161);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/24");

  script_cve_id("CVE-2019-5527");
  script_xref(name:"VMSA", value:"2019-0014");

  script_name(english:"VMSA-2019-0014 : Use-after-free vulnerability");
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
"ESXi use-after-free vulnerability - CVE-2019-5527

ESXi, Workstation, Fusion, VMRC and Horizon Client contain a use-after-free vulnerability in the virtual sound device.

A local attacker with non-administrative access on the guest machine may exploit this issue to execute code on the host. This issue can only be exploited if a valid sound back-end is not connected."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2019/000468.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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


init_esx_check(date:"2019-09-19");
flag = 0;


if (esx_check(ver:"ESXi 6.0", vib:"VMware:esx-base:6.0.0-3.125.14475122")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:vsan:6.0.0-3.125.14292904")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:vsanhealth:6.0.0-3000000.3.0.3.125.14292905")) flag++;

if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-base:6.5.0-2.83.13004031")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-tboot:6.5.0-2.83.13004031")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsan:6.5.0-2.83.12559347")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsanhealth:6.5.0-2.83.12559353")) flag++;

if (esx_check(ver:"ESXi 6.7", vib:"VMware:esx-base:6.7.0-1.44.12986307")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:esx-update:6.7.0-1.44.12986307")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:vsan:6.7.0-1.44.11399678")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:vsanhealth:6.7.0-1.44.11399680")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2018-0018. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(111350);
  script_version("1.5");
  script_cvs_date("Date: 2020/01/10");

  script_cve_id("CVE-2018-6971", "CVE-2018-6972");
  script_xref(name:"VMSA", value:"2018-0018");

  script_name(english:"VMSA-2018-0018 : VMware Horizon View Agent, VMware ESXi, Workstation, and Fusion updates resolve multiple security issues");
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
"a. VMware Horizon View Agent local information disclosure vulnerability

VMware Horizon View Agents contain a local information disclosure 
vulnerability due to insecure logging of credentials in the
vmmsi.log file when an account other than the currently logged on
user is specified during installation (including silent
installations). Successful exploitation of this issue may allow low
privileged users access to the credentials specified during the
Horizon View Agent installation.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifier CVE-2018-6971 to this issue.

b. ESXi, Workstation, and Fusion denial-of-service vulnerability

VMware ESXi, Workstation, and Fusion contain a denial-of-service 
vulnerability due to NULL pointer dereference issue in RPC handler. 
Successful exploitation of this issue may allow attackers with 
normal user privileges to crash their VMs.

VMware would like to thank Hahna Latonick and Kevin Fujimoto working 
with Trend Micro's Zero Day Initiative for reporting this issue to 
us.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifier CVE-2018-6972 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2018/000423.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.7");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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


init_esx_check(date:"2018-07-19");
flag = 0;


if (esx_check(ver:"ESXi 5.5", vib:"VMware:esx-base:5.5.0-3.117.8934887")) flag++;

if (esx_check(ver:"ESXi 6.0", vib:"VMware:esx-base:6.0.0-3.87.8934903")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:vsan:6.0.0-3.87.8155259")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:vsanhealth:6.0.0-3000000.3.0.3.87.8155260")) flag++;

if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-base:6.5.0-2.54.8935087")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-tboot:6.5.0-2.54.8935087")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsan:6.5.0-2.54.8359236")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsanhealth:6.5.0-2.54.8359237")) flag++;

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

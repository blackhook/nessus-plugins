#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2019-0022. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(132017);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/25");

  script_cve_id("CVE-2019-5544");
  script_xref(name:"VMSA", value:"2019-0022");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"VMSA-2019-0022 : VMware ESXi updates address OpenSLP remote code execution vulnerability");
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
"VMware ESXi updates address OpenSLP remote code execution
vulnerability (CVE-2019-5544)

OpenSLP as used in ESXi has a heap overwrite issue. A malicious actor
with network access to port 427 on an ESXi host may be able to
overwrite the heap of the OpenSLP service resulting in remote code
execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2019/000479.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5544");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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


init_esx_check(date:"2019-12-05");
flag = 0;


if (esx_check(ver:"ESXi 6.0", vib:"VMware:esx-base:6.0.0-3.138.15169789")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:vsan:6.0.0-3.138.15080872")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:vsanhealth:6.0.0-3000000.3.0.3.138.15080873")) flag++;

if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-base:6.5.0-3.111.15177306")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-tboot:6.5.0-3.111.15177306")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsan:6.5.0-3.111.15079806")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsanhealth:6.5.0-3.111.15079807")) flag++;

if (esx_check(ver:"ESXi 6.7", vib:"VMware:esx-base:6.7.0-3.85.15160134")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:esx-update:6.7.0-3.85.15160134")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:tools-light:11.0.1.14773994-15160134")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:vsan:6.7.0-3.85.14840325")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:vsanhealth:6.7.0-3.85.14840327")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

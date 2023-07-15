#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2020-0018. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(139849);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/04");

  script_cve_id("CVE-2020-3976");
  script_xref(name:"VMSA", value:"2020-0018");
  script_xref(name:"IAVA", value:"2020-A-0386");

  script_name(english:"VMSA-2020-0018 : VMware ESXi, vCenter Server, and Cloud Foundation updates address a partial denial of service vulnerability");
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
"a. Partial denial of service vulnerability via authentication services
(CVE-2020-3976)

VMware ESXi and vCenter Server contain a partial denial of service
vulnerability in their respective authentication services. A malicious
actor with network access to ESXi or vCenter may be able to exploit
this vulnerability to exhaust memory resources resulting in a
degradation of performance condition while the attack is sustained."
  );
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2020/000506.html");
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3976");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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


init_esx_check(date:"2020-08-20");
flag = 0;


if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-base:6.5.0-3.134.16576879")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-tboot:6.5.0-3.134.16576879")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsan:6.5.0-3.134.16576881")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsanhealth:6.5.0-3.134.16576882")) flag++;

if (esx_check(ver:"ESXi 6.7", vib:"VMware:esx-base:6.7.0-3.112.16701467")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:esx-update:6.7.0-3.112.16701467")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:vsan:6.7.0-3.112.16631637")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:vsanhealth:6.7.0-3.112.16631640")) flag++;

if (esx_check(ver:"ESXi 7.0", vib:"VMware:cpu-microcode:7.0.0-1.20.16321839")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:crx:7.0.0-1.20.16321839")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:esx-base:7.0.0-1.20.16321839")) flag++;
if (
  esx_check(
    ver : "ESXi 7.0",
    vib : "VMware:esx-dvfilter-generic-fastpath:7.0.0-1.20.16321839"
  )
) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:esx-ui:1.34.0-15603211")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:esx-update:7.0.0-1.20.16321839")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:esx-xserver:7.0.0-1.20.16321839")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:loadesx:7.0.0-1.20.16321839")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:native-misc-drivers:7.0.0-1.20.16321839")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:tools-light:11.1.0.16036546-16321839")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:vdfs:7.0.0-1.20.16321839")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:vsan:7.0.0-1.20.16321839")) flag++;
if (esx_check(ver:"ESXi 7.0", vib:"VMware:vsanhealth:7.0.0-1.20.16321839")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:esx_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

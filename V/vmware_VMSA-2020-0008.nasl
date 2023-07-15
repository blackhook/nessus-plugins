#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2020-0008. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(136174);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/28");

  script_cve_id("CVE-2020-3955");
  script_xref(name:"VMSA", value:"2020-0008");
  script_xref(name:"IAVA", value:"2020-A-0193-S");

  script_name(english:"VMSA-2020-0008 : VMware ESXi patches address Stored Cross-Site Scripting (XSS) vulnerability");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESXi host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. VMware ESXi patches address Stored Cross-Site Scripting (XSS) vulnerability (CVE-2020-3955)

Description :
The VMware ESXi Host Client does not properly neutralize
script-related HTML when viewing virtual machines attributes.

A malicious actor with access to modify the system properties of a
virtual machine from inside the guest os (such as changing the
hostname of the virtual machine) may be able to inject malicious
script which will be executed by a victim's browser when viewing this
virtual machine via the ESXi Host Client."
  );
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2020/000490.html");
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3955");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/30");
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


init_esx_check(date:"2020-04-28");
flag = 0;


if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-ui:1.33.5-15102916")) flag++;

if (esx_check(ver:"ESXi 6.7", vib:"VMware:esx-ui:1.33.7-15803439")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:esx_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

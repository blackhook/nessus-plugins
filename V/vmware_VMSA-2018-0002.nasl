#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2018-0002. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(105584);
  script_version("3.9");
  script_cvs_date("Date: 2018/08/06 14:03:16");

  script_cve_id("CVE-2017-5715", "CVE-2017-5753");
  script_xref(name:"VMSA", value:"2018-0002");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"VMSA-2018-0002 : VMware ESXi, Workstation and Fusion updates address side-channel analysis due to speculative execution. (Spectre)");
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
"Bounds Check bypass and Branch Target Injection issues

CPU data cache timing can be abused to efficiently leak information
out of mis-speculated CPU execution, leading to (at worst) arbitrary
virtual memory read vulnerabilities across local security boundaries
in various contexts. (Speculative execution is an automatic and
inherent CPU performance optimization used in all modern processors.)
ESXi, Workstation and Fusion are vulnerable to Bounds Check Bypass
and Branch Target Injection issues resulting from this vulnerability.

Result of exploitation may allow for information disclosure from one
Virtual Machine to another Virtual Machine that is running on the
same host. The remediation listed in the table below is for the known
variants of the Bounds Check Bypass and Branch Target Injection
issues.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the identifiers CVE-2017-5753 (Bounds Check bypass) and
CVE-2017-5715 (Branch Target Injection) to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2018/000400.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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


init_esx_check(date:"2018-01-03");
flag = 0;


if (esx_check(ver:"ESXi 5.5", vib:"VMware:esx-base:5.5.0-3.103.6480267")) flag++;

if (esx_check(ver:"ESXi 6.0", vib:"VMware:esx-base:6.0.0-3.76.6856897")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:vsan:6.0.0-3.76.6769077")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:vsanhealth:6.0.0-3000000.3.0.3.76.6769078")) flag++;

if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-base:6.5.0-1.33.7273056")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-tboot:6.5.0-1.33.7273056")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsan:6.5.0-1.33.6852403")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsanhealth:6.5.0-1.33.6852404")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:esx_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

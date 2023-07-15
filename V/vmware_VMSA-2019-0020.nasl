#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2019-0020. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(131018);
  script_version("1.4");
  script_cvs_date("Date: 2019/12/13");

  script_cve_id("CVE-2018-12207", "CVE-2019-11135");
  script_xref(name:"VMSA", value:"2019-0020");

  script_name(english:"VMSA-2019-0020 : Hypervisor-Specific Mitigations for Denial-of-Service and Speculative-Execution Vulnerabilities");
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
"a. Hypervisor-Specific Mitigations for Machine Check Error on Page Size Change (MCEPSC) Denial-of-Service vulnerability - CVE-2018-12207

VMware ESXi, Workstation, and Fusion patches include Hypervisor-Specific Mitigations for Machine Check Error on Page Size Change (MCEPSC).

A malicious actor with local access to execute code in a virtual machine may be able to trigger a purple diagnostic screen or immediate reboot of the Hypervisor hosting the virtual machine, resulting in a denial-of-service condition.
 
Because the mitigations for CVE-2018-12207 may have a performance impact they are not enabled by default. After applying patches, the mitigation can be enabled by following the instructions found in the article at https://kb.vmware.com/s/article/59139 . Performance impact data found in KB76050 should be reviewed prior to enabling this mitigation.

b. Hypervisor-Specific Mitigations for TSX Asynchronous Abort (TAA) Speculative-Execution vulnerability - CVE-2019-11135

VMware ESXi, Workstation, and Fusion patches include Hypervisor-Specific Mitigations for TSX Asynchronous Abort (TAA).

A malicious actor with local access to execute code in a virtual machine may be able to infer data otherwise protected by architectural mechanisms from another virtual machine or the hypervisor itself. This vulnerability is only applicable to Hypervisors utilizing 2nd Generation Intel Xeon Scalable Processors (formerly known as Cascade Lake) microarchitecture."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2019/000477.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11135");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/14");
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


init_esx_check(date:"2019-11-12");
flag = 0;


if (esx_check(ver:"ESXi 6.0", vib:"VMware:cpu-microcode:6.0.0-3.135.15018929")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:esx-base:6.0.0-3.135.15018929")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:vsan:6.0.0-3.135.14676868")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:vsanhealth:6.0.0-3000000.3.0.3.135.14676869")) flag++;

if (esx_check(ver:"ESXi 6.5", vib:"VMware:cpu-microcode:6.5.0-3.108.14990892")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-base:6.5.0-3.108.14990892")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-tboot:6.5.0-3.108.14990892")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsan:6.5.0-3.108.14833668")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsanhealth:6.5.0-3.108.14833669")) flag++;

if (esx_check(ver:"ESXi 6.7", vib:"VMware:cpu-microcode:6.7.0-3.77.15018017")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:esx-base:6.7.0-3.77.15018017")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:esx-update:6.7.0-3.77.15018017")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:vsan:6.7.0-3.77.14914424")) flag++;
if (esx_check(ver:"ESXi 6.7", vib:"VMware:vsanhealth:6.7.0-3.77.14914425")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:esx_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

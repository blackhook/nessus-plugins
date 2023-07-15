#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2018-0004. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(105768);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2017-5715");
  script_xref(name:"VMSA", value:"2018-0004");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"VMSA-2018-0004 : VMware vSphere, Workstation and Fusion updates add Hypervisor-Assisted Guest Remediation for speculative execution issue (Spectre)");
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
"New speculative-execution control mechanism for Virtual Machines

Updates of vCenter Server, ESXi, Workstation and Fusion virtualize
the new speculative-execution control mechanism for Virtual Machines
(VMs). As a result, a patched Guest Operating System (Guest OS) can
remediate the Branch Target Injection issue (CVE-2017-5715). This
issue may allow for information disclosure between processes within
the VM.

To remediate CVE-2017-5715 in the Guest OS the following VMware and
third-party requirements must be met :

VMware Requirements
-------------------

- Deploy the updated version of vCenter Server listed in the table
  (if vCenter Server is used).

- Deploy the ESXi patches and/or the new versions for Workstation or
  Fusion listed in the table.

- Ensure that your VMs are using Hardware Version 9 or higher. For
  best performance, Hardware Version 11 or higher is recommended.
  VMware Knowledge Base article 1010675 discusses Hardware Versions.

Third-party Requirements
------------------------

- Deploy the Guest OS patches for CVE-2017-5715. These patches are
  to be obtained from your OS vendor.

- Update the CPU microcode. Additional microcode is needed for your
  CPU to be able to expose the new MSRs that are used by the patched
  Guest OS. This microcode should be available from your hardware
  platform vendor.
  VMware is providing several versions of the required microcode from
  INTEL and AMD through ESXi patches listed in the table. See VMware
  Knowledge Base 52085 for more details."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2018/000399.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/12");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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


init_esx_check(date:"2018-01-09");
flag = 0;


if (esx_check(ver:"ESXi 5.5", vib:"VMware:cpu-microcode:5.5.0-3.114.7967571")) flag++;
if (esx_check(ver:"ESXi 5.5", vib:"VMware:esx-base:5.5.0-3.114.7967571")) flag++;

if (esx_check(ver:"ESXi 6.0", vib:"VMware:cpu-microcode:6.0.0-3.84.7967664")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:esx-base:6.0.0-3.84.7967664")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:vsan:6.0.0-3.84.7547427")) flag++;
if (esx_check(ver:"ESXi 6.0", vib:"VMware:vsanhealth:6.0.0-3000000.3.0.3.84.7547428")) flag++;

if (esx_check(ver:"ESXi 6.5", vib:"VMware:cpu-microcode:6.5.0-1.41.7967591")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-base:6.5.0-1.41.7967591")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:esx-tboot:6.5.0-1.41.7967591")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsan:6.5.0-1.41.7547709")) flag++;
if (esx_check(ver:"ESXi 6.5", vib:"VMware:vsanhealth:6.5.0-1.41.7547710")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:esx_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

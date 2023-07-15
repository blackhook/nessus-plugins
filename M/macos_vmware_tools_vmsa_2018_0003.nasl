#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105786);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/01");

  script_cve_id("CVE-2017-4945");
  script_bugtraq_id(102441);
  script_xref(name:"VMSA", value:"2018-0003");

  script_name(english:"VMware Tools < 10.2.0 Program Execution Vulnerability (VMSA-2018-0003) (macOS)");
  script_summary(english:"Checks the VMware Tools version.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote MacOS / MacOSX host is affected
by a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Tools installed on the remote MacOS/MacOSX host
is prior to 10.2.0. It is, therefore, affected by an unspecified flaw
in VMware Tools related to improper guest access control. This allows
a proximate attacker to execute programs via Unity mode on locked
Windows VMs.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2018-0003.html");
  # https://my.vmware.com/web/vmware/details?downloadGroup=VMTOOLS1020&productId=491
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d54c30a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMwware Tools version 10.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-4945");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:tools");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_vmware_tools_installed.nbin", "vmware_vsphere_detect.nbin");
  script_require_keys("installed_sw/VMware Tools", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("Host/MacOSX/Version");

rel   = get_kb_item_or_exit("Host/VMware/release");
if ("ESX" >!< rel || empty_or_null(rel))
  audit(AUDIT_OS_NOT, "VMware ESX/ESXi");	

app_info = vcf::get_app_info(app:"VMware Tools");

constraints = [{ "min_version" : "0", "fixed_version" : "10.2.0" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);

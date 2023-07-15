#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151285);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/30");

  script_cve_id("CVE-2021-21999");
  script_xref(name:"VMSA", value:"VMSA-2021-0013");
  script_xref(name:"IAVB", value:"2021-B-0037-S");

  script_name(english:"VMware Tools 11.x < 11.2.6 Privilege Escalation (VMSA-2021-0013)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization tool suite installed on the remote Windows host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Tools installed on the remote Windows host is 11.x prior to 11.2.6. It is, therefore, affected by
a local privilege escalation vulnerability. An attacker with normal access to a virtual machine may exploit this issue
by placing a malicious file renamed as 'openssl.cnf' in an unrestricted directory which would allow code to be executed
with elevated privileges.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2021-0013.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Tools version 11.2.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21999");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:tools");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_tools_installed.nbin", "vmware_vsphere_detect.nbin", "vmware_esxi_detection.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/VMware Tools", "Host/ESXi/checked");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit("SMB/Registry/Enumerated");

var app_info = vcf::get_app_info(app:'VMware Tools', win_local:TRUE);

var constraints = [
  { 'min_version' : '11.0', 'fixed_version' : '11.2.6' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
  );

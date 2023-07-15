#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177328);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/23");

  script_cve_id("CVE-2023-20867");
  script_xref(name:"VMSA", value:"2023-0013");
  script_xref(name:"IAVA", value:"2023-A-0288");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/07/14");

  script_name(english:"VMware Tools 10.3.x / 11.x / 12.x < 12.2.5 Authentication Bypass (VMSA-2023-0013)");

  script_set_attribute(attribute:"synopsis", value:
"The virtualization tool suite is installed on the remote Windows host is affected by an authentication bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Tools installed on the remote Windows host is affected by an authentication bypass vulnerability
in the vgauth module. A fully compromised ESXi host can force VMware Tools to fail to authenticate host-to-guest
operations, impacting the confidentiality and integrity of the guest virtual machine.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2023-0013.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Tools version 12.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:M/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20867");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:tools");
  script_set_attribute(attribute:"stig_severity", value:"III");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_tools_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/VMware Tools");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit("SMB/Registry/Enumerated");

var app_info = vcf::get_app_info(app:'VMware Tools', win_local:TRUE);
var constraints = [{ 'min_version' : '10.3', 'fixed_version' : '12.2.5' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);

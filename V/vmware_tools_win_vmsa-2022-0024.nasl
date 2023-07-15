#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164422);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2022-31676");
  script_xref(name:"VMSA", value:"VMSA-2022-0024");
  script_xref(name:"IAVB", value:"2022-B-0029-S");

  script_name(english:"VMware Tools 11.x / 12.x < 12.1.0 Privilege Escalation (VMSA-2022-0024)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization tool suite is installed on the remote Windows host is affected by a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Tools installed on the remote Windows host is affected by a privilege escalation vulnerability.
A malicious actor with local non-administrative access to the Guest OS can escalate privileges as a root user in the
virtual machine.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2022-0024.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Tools version 12.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31676");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:tools");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_tools_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/VMware Tools");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit("SMB/Registry/Enumerated");

var app_info = vcf::get_app_info(app:'VMware Tools', win_local:TRUE);
var constraints = [{ 'min_version' : '11.0', 'fixed_version' : '12.1.0' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

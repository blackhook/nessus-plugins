##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161605);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/30");

  script_cve_id("CVE-2022-22977");
  script_xref(name:"VMSA", value:"VMSA-2022-0015");
  script_xref(name:"IAVB", value:"2022-B-0014-S");

  script_name(english:"VMware Tools 10.x / 11.x / 12.x < 12.0.5 XXE (VMSA-2022-0015)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization tool suite is installed on the remote Windows host is affected by an XML External Entity
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Tools installed on the remote Windows host is affected by an XML External Entity (XXE)
vulnerability. A malicious actor with non-administrative local user privileges in the Windows guest OS, where VMware
Tools is installed, may exploit this issue leading to a denial-of-service condition or unintended information
disclosure.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2022-0015.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Tools version 12.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22977");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/27");

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
var constraints = [{ 'min_version' : '10.0', 'fixed_version' : '12.0.5' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);

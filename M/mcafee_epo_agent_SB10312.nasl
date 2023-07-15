##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(134762);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/27");

  script_cve_id("CVE-2020-7253");
  script_xref(name:"IAVA", value:"2020-A-0108");

  script_name(english:"McAfee Agent 5.5.x prior to 5.5.4 / 5.6.x prior to 5.6.4 Improper Access Control Vulnerability (SB10312)");
  script_summary(english:"Checks the McAfee Agent version.");

  script_set_attribute(attribute:"synopsis", value:
"A security management agent installed on the remote host is affected
by improper access control vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee Agent, formerly McAfee ePolicy Orchestrator (ePO) Agent, installed on the remote host is 5.5.x
prior to 5.5.4 / 5.6.x prior to 5.6.4. It is, therefore, affected by improper access control vulnerability. It allows
local users with administrator privileges to disable self-protection via a McAfee supplied command-line utility.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10312");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Agent version 5.5.4, 5.6.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7253");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator_agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:agent");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_epo_agent_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/McAfee ePO Agent");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'McAfee ePO Agent', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '5.5.0', 'fixed_version' : '5.5.4'},
  { 'min_version' : '5.6.0', 'fixed_version' : '5.6.4'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);

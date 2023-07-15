##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145262);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/27");

  script_cve_id("CVE-2020-7343");
  script_xref(name:"IAVA", value:"2021-A-0044-S");

  script_name(english:"McAfee Agent 5.6.x prior to 5.7.1 Missing Authorization (SB10343)");

  script_set_attribute(attribute:"synopsis", value:
"A security management agent installed on the remote host is affected by a missing authorization vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee Agent, formerly McAfee ePolicy Orchestrator (ePO) Agent, installed on the remote host is 5.6.x
prior to 5.7.1. It is, therefore, affected by a missing authorization vulnerability that allows local users to block
McAfee product updates by manipulating a directory used by MA for temporary files. The product would continue to
function with out-of-date detection files.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10343");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Agent version 5.7.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7343");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator_agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:agent");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_epo_agent_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/McAfee ePO Agent");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'McAfee ePO Agent', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '5.6.0', 'fixed_version' : '5.7.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);

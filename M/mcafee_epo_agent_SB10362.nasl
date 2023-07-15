#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150860);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/27");

  script_cve_id("CVE-2021-31839", "CVE-2021-31840");
  script_xref(name:"IAVA", value:"2021-A-0285-S");

  script_name(english:"McAfee Agent 5.x prior to 5.7.3 Multiple Vulnerabilities (SB10362)");

  script_set_attribute(attribute:"synopsis", value:
"A security management agent installed on the remote host is affected by a missing authorization vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee Agent, formerly McAfee ePolicy Orchestrator (ePO) Agent, installed on the remote host is 5.x
prior to 5.7.3. It is, therefore, affected by the following vulnerabilities:

  - An improper privilege management vulnerability exists due to a local user having the ability to edit the
    event log. An authenticated, attacker can exploit this, via by editing the agents event log prior to the
    events being sent to the ePO server. (CVE-2021-31839)
  
  - An unsigned DLL preloading attack vulnerability exists. An authenticated, local attacker can exploit this
    and load malicious libraries of functionality on the remote host due to an insufficient validation of
    resources loaded by the application at runtime. (CVE-2021-31840) 
  
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10362");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Agent version 5.7.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31840");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/18");

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

var app_info = vcf::get_app_info(app:'McAfee ePO Agent', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '5.0.0', 'fixed_version' : '5.7.3'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

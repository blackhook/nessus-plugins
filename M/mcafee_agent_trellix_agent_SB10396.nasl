#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175065);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/04");

  script_cve_id("CVE-2023-0975", "CVE-2023-0977");
  script_xref(name:"IAVA", value:"2023-A-0231");

  script_name(english:"Trellix Agent < 5.7.9 Multiple Vulnerabilities (SB10396)");

  script_set_attribute(attribute:"synopsis", value:
"A security management agent installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Trellix Agent, formerly McAfee Agent or McAfee Policy Orchestrator (ePO) Agent, installed on the remote
host is prior to 5.7.9. It is, therefore, affected by multiple vulnerabilities:

  - A vulnerability exists in TA for Windows 5.7.8 and earlier, which allows local users, during install/upgrade 
    workflow, to replace one of the Agent's executables before it can be executed. This allows the user to elevate 
    their permissions. (CVE-2023-0975)

  - A heap-based overflow vulnerability in TA (Windows and Linux) 5.7.8 and earlier allows a remote user to alter the 
    page heap in the macmnsvc process memory block, resulting in the service becoming unavailable. (CVE-2022-0977)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kcm.trellix.com/corporate/index?page=content&id=SB10396");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Agent version 5.7.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0975");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator_agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trellix:agent");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_epo_agent_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/McAfee ePO Agent");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'McAfee ePO Agent', win_local:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [{'fixed_version': '5.7.9'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);

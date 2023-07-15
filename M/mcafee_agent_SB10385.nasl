##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163587);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/05");

  script_cve_id("CVE-2022-2313");
  script_xref(name:"IAVA", value:"2022-A-0300-S");

  script_name(english:"McAfee Agent < 5.7.7 DLL Hijacking (SB10385)");

  script_set_attribute(attribute:"synopsis", value:
"A security management agent installed on the remote host is affected by a DLL hijacking vulnerability.");
  script_set_attribute(attribute:"description", value:
"A DLL hijacking vulnerability in the MA Smart Installer for Windows prior to 5.7.7, which allows local users to 
execute arbitrary code and obtain higher privileges via careful placement of a malicious DLL into the folder from where 
the Smart installer is being executed.
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kcm.trellix.com/corporate/index?page=content&id=SB10385");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Agent version 5.7.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2313");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator_agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:agent");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_epo_agent_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/McAfee ePO Agent");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'McAfee ePO Agent', win_local:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [{'fixed_version': '5.7.7'}];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);

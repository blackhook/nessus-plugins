#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153617);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/03");

  script_cve_id("CVE-2021-31836", "CVE-2021-31841", "CVE-2021-31847");
  script_xref(name:"IAVA", value:"2021-A-0436-S");

  script_name(english:"McAfee Agent < 5.7.4 Multiple Vulnerabilities (SB10369)");

  script_set_attribute(attribute:"synopsis", value:
"A security management agent installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee Agent, formerly McAfee ePolicy Orchestrator (ePO) Agent, installed on the remote host is prior to
5.7.4. It is, therefore, affected by the following vulnerabilities:

  - Improper access control vulnerability in the repair process for McAfee Agent for Windows prior to 5.7.4
    could allow a local attacker to perform a DLL preloading attack using unsigned DLLs. This would result in
    elevation of privileges and the ability to execute arbitrary code as the system user, through not
    correctly protecting a temporary directory used in the repair process and not checking the DLL signature.
    (CVE-2021-31847)

  - A DLL sideloading vulnerability in McAfee Agent for Windows prior to 5.7.4 could allow a local user to
    perform a DLL sideloading attack with an unsigned DLL with a specific name and in a specific location.
    This would result in the user gaining elevated permissions and the ability to execute arbitrary code as
    the system user, through not checking the DLL signature. (CVE-2021-31841)

  - Improper privilege management vulnerability in maconfig for McAfee Agent for Windows prior to 5.7.4 allows
    a local user to gain access to sensitive information. The utility was able to be run from any location on
    the file system and by a low privileged user. (CVE-2021-31836)

  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10369");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Agent version 5.7.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31847");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator_agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:agent");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_epo_agent_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/McAfee ePO Agent");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'McAfee ePO Agent', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '5.7.4'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

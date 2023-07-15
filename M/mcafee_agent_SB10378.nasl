#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157126);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id("CVE-2021-31854", "CVE-2022-0166");
  script_xref(name:"IAVA", value:"2022-A-0045-S");

  script_name(english:"McAfee Agent < 5.7.5 Multiple Vulnerabilities (SB10378)");

  script_set_attribute(attribute:"synopsis", value:
"A security management agent installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee Agent, formerly McAfee ePolicy Orchestrator (ePO) Agent, installed on the remote host is prior to
5.7.5. It is, therefore, affected by the following vulnerabilities:

  - A command Injection Vulnerability in McAfee Agent (MA) for Windows prior to 5.7.5 allows local users to 
    inject arbitrary shell code into the file cleanup.exe. The malicious clean.exe file is placed into the 
    relevant folder and executed by running the McAfee Agent deployment feature located in the System Tree.
    An attacker may exploit the vulnerability to obtain a reverse shell which can lead to privilege 
    escalation to obtain root privileges. (CVE-2021-31854)

  - A privilege escalation vulnerability in the McAfee Agent prior to 5.7.5. McAfee Agent uses openssl.cnf 
    during the build process to specify the OPENSSLDIR variable as a subdirectory within the installation 
    directory. A low privilege user could have created subdirectories and executed arbitrary code with SYSTEM
    privileges by creating the appropriate pathway to the specifically created malicious openssl.cnf file. 
    (CVE-2022-0166)
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10378");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Agent version 5.7.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31854");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0166");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator_agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:agent");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_epo_agent_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/McAfee ePO Agent");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'McAfee ePO Agent', win_local:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [{'fixed_version': '5.7.5'}];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_HOLE
);

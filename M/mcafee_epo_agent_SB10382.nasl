#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160054);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/09");

  script_cve_id("CVE-2022-1256", "CVE-2022-1257", "CVE-2022-1258");
  script_xref(name:"IAVA", value:"2022-A-0160-S");

  script_name(english:"McAfee Agent < 5.7.6 Multiple Vulnerabilities (SB10382)");

  script_set_attribute(attribute:"synopsis", value:
"A security management agent installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee Agent, formerly McAfee ePolicy Orchestrator (ePO) Agent, installed on the remote host is prior 
to 5.7.6. It is, therefore, affected by the following vulnerabilities:

  - A local privilege escalation vulnerability in MA for Windows prior to 5.7.6 allows a local low privileged
  user to gain system privileges through running the repair functionality. Temporary file actions were 
  performed on the local user's %TEMP% directory with System privileges through manipulation of symbolic 
  links. (CVE-2022-1256)

  - Insecure storage of sensitive information vulnerability in MA for Linux, macOS, and Windows prior to 5.7.6
  allows a local user to gain access to sensitive information through storage in ma.db. The sensitive 
  information has been moved to encrypted database files. (CVE-2022-1257)

  - A blind SQL injection vulnerability in the ePolicy Orchestrator (ePO) extension of MA prior to 5.7.6 can be
  exploited by an authenticated administrator on ePO to perform arbitrary SQL queries in the back-end database, 
  potentially leading to command execution on the server. (CVE-2022-1258)
  
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10382");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Agent version 5.7.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1256");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/21");

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

var constraints = [{'fixed_version' : '5.7.6'}];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_HOLE, 
  flags:{'sqli':TRUE}
);

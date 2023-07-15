#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125779);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id("CVE-2018-6705", "CVE-2018-6706", "CVE-2018-6707");
  script_bugtraq_id(106307, 106328);

  script_name(english:"McAfee Agent 5.0.x / 5.5.0 / 5.5.1 Multiple Vulnerabilities (SB10260)");

  script_set_attribute(attribute:"synopsis", value:
"A security management agent installed on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee Agent, formerly McAfee ePolicy Orchestrator
(ePO) Agent, installed on the remote host is 5.0.x, 5.5.0, or 5.5.1.
It is, therefore, affected by multiple vulnerabilities. These include
an arbitrary command execution and potentially a remote code execution
vulnerability. A local attacker could use these vulnerabilities to
potentially gain unauthorized access to the remote system.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10260");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Agent version 5.6.0, or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6706");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-6705");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator_agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:agent");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_epo_agent_installed_nix.nbin");
  script_exclude_keys("SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

# Non-Windows only
if (get_kb_item('SMB/Registry/Enumerated')) audit(AUDIT_OS_NOT, 'affected');

app_info = vcf::get_app_info(app:'McAfee ePO Agent');

vcf::check_granularity(app_info:app_info, sig_segments:3);

# Exact Build Numbers if needed:
#   https://kc.mcafee.com/corporate/index?page=content&id=KB51573
constraints = [
  { 'min_version' : '5.0', 'max_version' : '5.1', 'fixed_version' : '5.6.0'},
  { 'min_version' : '5.5.0', 'max_version' : '5.5.0.482', 'fixed_version' : '5.6.0'},
  { 'min_version' : '5.5.1', 'max_version' : '5.5.1.462', 'fixed_version' : '5.6.0'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

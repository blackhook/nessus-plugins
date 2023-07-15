#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157872);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/14");

  script_cve_id("CVE-2021-4088");
  script_xref(name:"MCAFEE-SB", value:"SB10376");
  script_xref(name:"IAVA", value:"2022-A-0061");

  script_name(english:"McAfee Data Loss Prevention ePO extension Blind SQLi (SB10376)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a blind SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of McAfee ePolicy Orchestrator that is affected by a blind SQL injection
vulnerability that allows a remote authenticated attacker to inject unfiltered SQL into the DLP part of the ePO
database. This could lead to remote code execution on the ePO server with privilege escalation.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10376");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version  11.8.100, 11.7.101, or 11.6.401, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4088");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:data_loss_prevention_endpoint");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_dlp_epo_extension_installed.nbin");
  script_require_keys("installed_sw/McAfee DLP ePO Extension", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'McAfee DLP ePO Extension', win_local:TRUE);

var constraints = [
  { 'fixed_version':'11.6.401'},
  { 'min_version':'11.7', 'fixed_version':'11.7.101' },
  { 'min_version':'11.8', 'fixed_version':'11.8.100' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'sqli':TRUE}
);


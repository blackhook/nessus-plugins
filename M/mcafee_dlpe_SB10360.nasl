#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150864);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/24");

  script_cve_id("CVE-2021-31832");
  script_xref(name:"MCAFEE-SB", value:"SB10360");
  script_xref(name:"IAVA", value:"2021-A-0284");

  script_name(english:"McAfee DLPe Agent < 11.6.200 Multiple Vulnerabilities (SB10360)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the McAfee Data Loss Prevention Endpoint (DLPe) Agent installed on the remote Windows host is prior to
11.6.200. Improper Neutralization of Input in the ePO administrator extension for McAfee Data Loss Prevention (DLP)
Endpoint for Windows prior to 11.6.200 allows a remote ePO DLP administrator to inject JavaScript code into the alert
configuration text field. This JavaScript will be executed when an end user triggers a DLP policy on their machine.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10360");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee DLPe 11.6.2001 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31832");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:data_loss_prevention_endpoint");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_dlpe_agent_installed.nbin");
  script_require_keys("installed_sw/McAfee DLPe Agent", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'McAfee DLPe Agent', win_local:TRUE);

var constraints = [{ 'fixed_version':'11.6.200' }];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);

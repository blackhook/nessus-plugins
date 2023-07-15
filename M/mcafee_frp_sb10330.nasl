#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141778);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/02");

  script_cve_id("CVE-2020-7316");
  script_xref(name:"IAVA", value:"2020-A-0466");

  script_name(english:"McAfee File and Removable Media Protection < 5.3.0.143 Arbitrary Code Execution Vulnerability (SB10330)");
  script_summary(english:"Checks the McAfee File and Removable Media Protection version.");

  script_set_attribute(attribute:"synopsis", value:
"A security management agent installed on the remote host is affected
by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee File and Removable Media Protection installed on the remote host is prior to 5.3.0.143. 
It is, therefore, affected by an arbitrary code execution vulnerability which allows
local users to execute arbitrary code, with higher privileges.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10330");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee File and Removable Media Protection version 5.3.0.143 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7316");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator_agent");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_frp_installed.nbin");

  exit(0);
}

include('vcf.inc');

if (get_kb_item('SMB/Registry/Enumerated')) win_local = TRUE;

app_info = vcf::get_app_info(app:'McAfee FRP', win_local:win_local);

vcf::check_granularity(app_info:app_info, sig_segments:4);

constraints = [
  { 'min_version' : '5.0.0.0', 'fixed_version' : '5.3.0.143'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

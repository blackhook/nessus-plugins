#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127116);
  script_version("1.3");
  script_cvs_date("Date: 2019/10/18 23:14:15");

  script_cve_id("CVE-2018-6664");
  script_bugtraq_id(104299);
  script_xref(name:"MCAFEE-SB", value:"SB10233");

  script_name(english:"McAfee DLPe Agent < 10.0.500 / 11.x < 11.0.400 Master Bypass Vulnerability (SB10233)");
  script_summary(english:"Checks the version of McAfee DLPe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a master bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the McAfee Data Loss Prevention Endpoint (DLPe) Agent installed on the remote Windows host is prior to
10.0.500 or 11.x prior to 11.0.400. It is, therefore, affected by a master bypass vulnerability. An authenticated
attacker can exploit this issue using a command line utility to bypass the product block option.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10233");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee DLPe 10.0.500 or 11.0.400 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6664");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:data_loss_prevention_endpoint");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_dlpe_agent_installed.nbin");
  script_require_keys("installed_sw/McAfee DLPe Agent", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"McAfee DLPe Agent", win_local:TRUE);

constraints = [
  { "fixed_version":"10.0.500" },
  { "min_version":"11.0", "fixed_version":"11.0.400" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

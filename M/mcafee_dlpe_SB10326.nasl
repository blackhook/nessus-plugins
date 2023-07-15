#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139732);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/24");

  script_cve_id("CVE-2020-7306", "CVE-2020-7307");
  script_xref(name:"MCAFEE-SB", value:"SB10326");
  script_xref(name:"IAVA", value:"2020-A-0378");

  script_name(english:"McAfee MacOSX DLPe Agent 11.3.x < 11.3.31 / 11.4.x < 11.4.200 / 11.5.x < 11.5.2 Multiple Vulnerabilities (SB10326)");
  script_summary(english:"Checks the version of McAfee DLPe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the McAfee Data Loss Prevention Endpoint (DLPe) Agent installed on the remote MacOSX host is 11.3.x
prior to 11.3.31, 11.4.x prior to 11.4.200, or 11.5.x prior to 11.5.2. It is, therefore, affected by multiple vulnerabilities:

  - Unprotected Storage of Credentials vulnerability in McAfee Data Loss Prevention (DLP) for Mac allows local 
    users to gain access to the ADRMS username and password via unprotected log files containing plain text 
    credentials. (CVE-2020-7306)

  - Unprotected Storage of Credentials vulnerability in McAfee Data Loss Prevention (DLP) for Mac allows local 
  users to gain access to the RiskDB username and password via unprotected log files containing plain text 
  credentials. (CVE-2020-7307)");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10326");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee DLPe 11.3.31 or 11.4.200 or 11.5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7307");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:data_loss_prevention_endpoint");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_mcafee_dlpe_agent_installed.nbin");
  script_require_keys("installed_sw/McAfee DLPe Agent", "Host/MacOSX/Version");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/MacOSX/Version');

app_info = vcf::get_app_info(app:'McAfee DLPe Agent');

constraints = [
  { 'min_version':'11.3', 'fixed_version':'11.3.31' },
  { 'min_version':'11.4', 'fixed_version':'11.4.200' },
  { 'min_version':'11.5', 'fixed_version':'11.5.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);


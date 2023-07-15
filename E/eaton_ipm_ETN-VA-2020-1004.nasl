#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136766);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2020-6651", "CVE-2020-6652");
  script_xref(name:"IAVA", value:"2020-A-0224-S");

  script_name(english:"Eaton Intelligent Power Manager (IPM) < 1.68 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web application development suite installed on the remote Windows
host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Eaton Intelligent Power Manager (IPM) v1.67 and prior contain multiple vulnerabilities:

- Improper Input Validation on file name during configuration file import functionality 
allows attackers to perform command injection or code execution via specially crafted 
file names while uploading the configuration file in the application (CVE-2020-6651).

- Incorrect Privilege Assignment vulnerability allows non-admin users to upload the system 
configuration files by sending specially crafted requests. This can result in non-admin 
users manipulating the system configurations via uploading the configurations with 
incorrect parameters (CVE-2020-6652).");
  # https://www.eaton.com/content/dam/eaton/company/news-insights/cybersecurity/security-bulletins/eaton-vulnerability-advisory-intelligent-power-manager-v1-1.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20ae4ece");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Eaton IPM v1.68 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6651");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-6652");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:eaton:intelligent_power_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("eaton_ipm_win_installed.nbin");
  script_require_keys("installed_sw/Eaton Intelligent Power Manager");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit("SMB/Registry/Enumerated");
 
app_info = vcf::get_app_info(app:"Eaton Intelligent Power Manager");

constraints = [
  { 'min_version' : '1.0', 'fixed_version' : '1.68' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137180);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/05");

  script_cve_id("CVE-2020-4020");
  script_xref(name:"IAVA", value:"2020-A-0242-S");

  script_name(english:"Atlassian Companion < 1.0.0  Protection Mechanism Failure");

  script_set_attribute(attribute:"synopsis", value:
"A development edition application installed on the remote Windows
host is affected by local Protection Mechanism Failure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The file downloading functionality in the Atlassian Companion App before version 1.0.0 
allows remote attackers, who control a Confluence Server instance that the Companion App 
is connected to, execute arbitrary .exe files via a Protection Mechanism Failure.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-59733");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Companion 1.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4020");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:companion");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("atlassian_companion_win_installed.nbin");
  script_require_keys("installed_sw/Atlassian Companion");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit("SMB/Registry/Enumerated");
 
app_info = vcf::get_app_info(app:"Atlassian Companion");

constraints = [
  { 'min_version' : '0.5.3', 'fixed_version' : '1.0.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128685);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/27");

  script_cve_id("CVE-2019-1622");
  script_bugtraq_id(108908);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo64654");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190626-dcnm-infodiscl");
  script_xref(name:"IAVA", value:"2019-A-0221");

  script_name(english:"Cisco Data Center Network Manager Information Disclosure Vulnerability");
  script_summary(english:"Checks the version of Cisco Data Center Network Manager");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"An information disclosure vulnerability exists in the web-based management interface of Cisco Data Center Network
Manager (DCNM) due to improper access controls for certain URLs on affected DCNM software. An unauthenticated,
remote attacker can exploit this, by connecting to the web-based management interface of an affected device and
requesting specific URLs, to disclose potentially sensitive information.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a77dc334");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo64654");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo64654");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1622");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cisco Data Center Network Manager Unauthenticated Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:data_center_network_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("cisco_prime_dcnm_installed_win.nasl", "cisco_prime_dcnm_installed_linux.nasl");
  script_require_keys("installed_sw/Cisco Prime DCNM");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('vcf.inc');

app = 'Cisco Prime DCNM';

get_install_count(app_name:app, exit_if_zero:TRUE);

app_info = vcf::get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'fixed_version' : '11.2.1.0', 'fixed_display' : '11.2(1)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
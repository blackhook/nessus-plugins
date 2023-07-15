#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138601);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/05");

  script_cve_id("CVE-2020-5352");
  script_xref(name:"IAVB", value:"2020-B-0038-S");

  script_name(english:"EMC Data Protection Advisor 6.4 / 6.5 / 18.1 OS Command Injection (DSA-2020-081)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by an OS command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EMC Protection Advisor installed on the remote host is 6.4, 6.5 or 18.1. It is, therefore, affected by
an OS command injection vulnerability. An authenticated, remote attacker can exploit this to execute arbitrary commands
on the affected system.");
  # https://www.dell.com/support/security/en-ie/details/542719/DSA-2020-081-Dell-EMC-Data-Protection-Advisor-OS-Command-Injection-Vulnerability#
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac26bb32");
  script_set_attribute(attribute:"solution", value:
"Upgrade EMC Protection Advisor to version 18.2, 19.1, 19.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5352");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:data_protection_advisor");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("win_emc_dpa_installed.nbin");
  script_require_keys("installed_sw/EMC Data Protection Advisor");

  exit(0);
}

include('vcf.inc');
include('audit.inc');

app_name = 'EMC Data Protection Advisor';
app_info = vcf::get_app_info(app:app_name);
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version' : '6.4', 'fixed_version' : '6.6', 'fixed_display' : '18.2, 19.1, 19.2 or later' },
  { 'min_version' : '18.1', 'fixed_version' : '18.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

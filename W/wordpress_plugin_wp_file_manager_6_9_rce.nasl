#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140211);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/27");

  script_cve_id("CVE-2020-25213");
  script_xref(name:"IAVA", value:"2020-A-0425");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0115");

  script_name(english:"WordPress Plugin 'File Manager' 6.x < 6.9 Remote Code Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote WordPress application has a plugin installed that is vulnerable to a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The WordPress application running on the remote host has a version of the 'File Manager' plugin that is 6.x prior to
6.9. It is, therefore, affected by a remote code execution vulnerability due to improper inclusion of elFinder. An
unauthenticated, remote attacker can exploit this, by sending a specially crafted request to the connector.minimal.php
file, to gain remote code execution on the vulnerable WordPress site.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://www.wordfence.com/blog/2020/09/700000-wordpress-users-affected-by-zero-day-vulnerability-in-file-manager-plugin/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53de38d7");
  script_set_attribute(attribute:"solution", value:
"Upgrade the 'File Manager' plugin to version 6.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25213");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"WordPress File Manager < 6.9 File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'WordPress File Manager Unauthenticated Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_plugin_detect.nbin");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::wordpress::plugin::get_app_info(plugin:'wp-file-manager');
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version' : '6.0', 'fixed_version' : '6.9' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);


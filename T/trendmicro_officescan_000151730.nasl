#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133269);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2019-18187");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Trend Micro OfficeScan Directory Traversal Vulnerability (000151730)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application that is affected by a 
 directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Trend Micro engine which is affected by a directory traversal 
vulnerability. An unauthenticated, remote attacker can exploit this, by sending a URI that contains directory traversal 
characters, to extract files from an arbitrary zip file to a specific folder on the OfficeScan server, which could 
potentially lead to remote code execution (RCE)");
  # https://success.trendmicro.com/solution/000151730
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29284da6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Trend Micro 
 advisory 000151730.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18187");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("trendmicro_officescan_detect.nbin");
  script_require_keys("installed_sw/Trend Micro OfficeScan");
  script_require_ports("Services/www", 4343, 8080);

  exit(0);
}


include('http_func.inc');
include('lists.inc');
include('vcf.inc');

app = 'Trend Micro OfficeScan';
port = get_http_port(default:4343);

get_install_count(app_name:app, exit_if_zero:TRUE);
app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:4);

sp1 = 'Service Pack 1' >< app_info['Source'];

# 11.x Non SP1 not affected.
if (!sp1 && app_info['version'] =~ '^11\\.0')
  audit(AUDIT_HOST_NOT, 'affected');

constraints = [];
if (sp1)
{
  collib::push({'min_version' : '11.0', 'fixed_version' : '11.0.0.6638', 'fixed_display' : '11.0 CP 6638'}, list:constraints);
  collib::push({'min_version' : '12.0', 'fixed_version' : '12.0.0.5427', 'fixed_display' : '12.0 CP 5427'}, list:constraints);
}
else
{
  collib::push({'min_version' : '12.0', 'fixed_version' : '12.0.0.1962', 'fixed_display' : '12.0 CP 1962'}, list:constraints);
}

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);

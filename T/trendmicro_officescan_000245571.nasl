#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134629);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-8467",
    "CVE-2020-8468",
    "CVE-2020-8470",
    "CVE-2020-8598",
    "CVE-2020-8599"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0029");

  script_name(english:"Trend Micro OfficeScan Multiple Vulnerabilities (000245571)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Trend Micro OfficeScan application running 
on the remote host is prior to 12.0 CP 5474 (XG SP1) or 12.0 CP 1988 (XG). It is, therefore, 
affected by multiple vulnerabilities.

-   A remote code execution vulnerability exists due to a 
    unsecured dll. An unauthenticated, remote attacker can 
    exploit this to bypass authentication and execute 
    arbitrary commands with root privileges. 
    (CVE-2020-8598), (CVE-2020-8470)
    
 -  A privilege escalation vulnerability exists due to a 
    vulnerable EXE file. An unauthenticated, remote attacker 
    can exploit this to gain root access to the system.
    (CVE-2020-8599)
    
-   A remote code execution vulnerability exists due to a 
    migration tool component vulnerability. An authenticated, 
    remote attacker can exploit this to bypass authentication 
    and execute arbitrary commands with root privileges. 
    (CVE-2020-8467)
    
-   A content validation escape vulnerability exist in the 
    agent client components that could allow a authenticated 
    remote attacker to manipulate OfficeScan components.
    (CVE-2020-8468)");
  # https://success.trendmicro.com/portal_kb_articledetail?solutionid=000245571
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e02f3e83");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Trend Micro 
 advisory 000245571.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8599");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/18");

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
constraints = [];

# Fix version different depending on whether the host has SP1 or not
if ('Service Pack 1' >< app_info['Source'])
{
  collib::push(
    {'min_version' : '0.0', 'fixed_version' : '12.0.0.5474', 'fixed_display' : '12.0 CP 5474'},
    list:constraints
  );
}
else
{
  collib::push(
    {'min_version' : '0.0', 'fixed_version' : '12.0.0.1988', 'fixed_display' : '12.0 CP 1988'},
    list:constraints
  );
}

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(149064);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-24557", "CVE-2020-24558");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Trend Micro OfficeScan Multiple Vulnerabilities (000263632)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Trend Micro OfficeScan application running on the remote host is prior to 
XG SP1 CP 5698. It is, therefore, affected by multiple vulnerabilities:

  - An improper access control privilege escalation in Trend Micro Apex One and OfficeScan XG SP1 on Microsoft
    Windows may allow an attacker to manipulate a particular product folder to disable the security
    temporarily, abuse a specific Windows function and attain privilege escalation. An attacker must first
    obtain the ability to execute low-privileged code on the target system in order to exploit this
    vulnerability. Please note that version 1909 (OS Build 18363.719) of Microsoft Windows 10 mitigates hard
    links, but previous versions are affected. (CVE-2020-24557)

  - An out-of-bounds read information disclosure vulnerability in Trend Micro Apex One and OfficeScan XG SP1
    dll may allow an attacker to manipulate it to cause an out-of-bounds read that crashes multiple processes
    in the product. An attacker must first obtain the ability to execute low-privileged code on the target
    system in order to exploit this vulnerability. (CVE-2020-24558)

Please note that one of the OfficeScan XG SP1 vulnerabilities was addressed in a previous patch than the one listed,
however, it is always recommended to get the latest known version for complete mitigation. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://success.trendmicro.com/solution/000263632");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OfficeScan XG SP1 CP 5698 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24557");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trend_micro:officescan");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("trendmicro_officescan_detect.nbin");
  script_require_keys("installed_sw/Trend Micro OfficeScan");
  script_require_ports("Services/www", 4343, 8080);

  exit(0);
}

include('http_func.inc');
include('vcf.inc');

var app = 'Trend Micro OfficeScan';
var port = get_http_port(default:4343);
get_install_count(app_name:app, exit_if_zero:TRUE);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:4);
if ('Service Pack 1' >!< app_info['Source']) audit(AUDIT_HOST_NOT, 'affected');

var constraints = [{'fixed_version' : '12.0.0.5698', 'fixed_display' : 'XG SP1 CP 5698'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

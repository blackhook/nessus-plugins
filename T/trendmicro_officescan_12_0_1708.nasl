#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103968);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

  script_cve_id(
    "CVE-2017-14083",
    "CVE-2017-14084",
    "CVE-2017-14085",
    "CVE-2017-14086",
    "CVE-2017-14087",
    "CVE-2017-14088",
    "CVE-2017-14089"
  );
  script_bugtraq_id(97541);
  script_xref(name:"ZDI", value:"ZDI-17-828");
  script_xref(name:"ZDI", value:"ZDI-17-829");
  script_xref(name:"EDB-ID", value:"42920");

  script_name(english:"Trend Micro OfficeScan cgiShowClientAdm Remote Memory Corruption");
  script_summary(english:"Checks for OfficeScan version.");

  script_set_attribute(attribute:"synopsis", value:
"A CGI application running on the remote host is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Trend Micro OfficeScan running on the remote host
is 11.x prior to 11.0 SP1 CP 6426, or 12.x prior to 12.0 CP 1708.
It is, therefore, affected by a remote memory corruption flaw in
cgiShowClientAdm.exe due to improper input validation. An
unauthenticated remote attacker can corrupt memory and cause a denial
of service or potentially execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://success.trendmicro.com/solution/1118372");
  # http://hyp3rlinx.altervista.org/advisories/CVE-2017-14089-TRENDMICRO-OFFICESCAN-XG-PRE-AUTH-REMOTE-MEMORY-CORRUPTION.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01a56418");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2017/Sep/91");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Trend Micro OfficeScan 11.0 SP1 CP 6426 / XG (12.0) CP 1708
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14089");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Trend Micro OfficeScan 11.0/XG Encryption Key Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trend_micro:officescan");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("trendmicro_officescan_detect.nbin");
  script_require_keys("installed_sw/Trend Micro OfficeScan");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 4343, 8080);

  exit(0);
}

include("vcf.inc");
include("http_func.inc");

app = 'Trend Micro OfficeScan';

port = get_http_port(default:4343, embedded:TRUE);

get_install_count(app_name:app, exit_if_zero:TRUE);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:4);

constraints = [
 {"min_version" : "11.0", "fixed_version" : "11.0.0.6426", "fixed_display" : "11.0 SP1 Patch 1 CP 6426"},
 {"min_version" : "12.0", "fixed_version" : "12.0.0.1708", "fixed_display" : "12.0 CP 1708"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

#
# (C) Tenable Network Security, Inc.
#




include("compat.inc");

if (description)
{
  script_id(110557);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2017-7310");
  script_xref(name:"EDB-ID", value:"40455");

  script_name(english:"VX Search HTTP POST Request Handling Remote Stack Buffer Overflow");
  script_summary(english:"The remote host is affected by a buffer overflow vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"VX Search product contains an overflow condition that is triggered
   when handling overly large HTTP POST requests e.g. sent to /login. 
   This may allow a remote attacker to cause a stack-based buffer 
   overflow and execute arbitrary code.");
  # https://packetstormsecurity.com/files/138995/VX-Search-Enterprise-9.0.26-Buffer-Overflow.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91a4ce40");
  script_set_attribute(attribute:"see_also", value:"https://vxsearch.com");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VX Search 10.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7310");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sync Breeze Enterprise 9.5.16 - Import Command Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:flexense:vxsearch");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("flexense_detect.nbin");
  script_require_keys("installed_sw/VX Search");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http.inc");
include("vcf.inc");

appname = 'VX Search';

get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:80);

app_info = vcf::get_app_info(app:appname, port:port, webapp:TRUE);

constraints = [
  { "min_version" : "1.0", "max_version" : "10.5", "fixed_version" : "10.6" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
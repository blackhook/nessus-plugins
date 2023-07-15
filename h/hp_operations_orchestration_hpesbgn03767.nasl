#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102959);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-8994");
  script_xref(name:"IAVB", value:"2017-B-0117");

  script_name(english:"HP Operations Orchestration 10.x < 10.80 Remote Code Execution");
  script_summary(english:"Checks the HP Operations Orchestration version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP Operations Orchestration running on the remote host
is 10.x prior to 10.80. It is, therefore, affected by a remote code
execution vulnerability as described in HPESBGN03767.");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbgn03767en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5ea413f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Operations Orchestration version 10.80 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8994");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:operations_orchestration");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_operations_orchestration_detect.nbin");
  script_require_keys("installed_sw/HP Operations Orchestration");
  script_require_ports("Services/www", 8080, 8443);

  exit(0);
}

include("vcf.inc");
include("http.inc");

appname = "HP Operations Orchestration";
get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:8080);

app_info = vcf::get_app_info(app:appname, port:port, webapp:TRUE);


constraints = [{"min_version" : "10", "fixed_version" : "10.80" }];


vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
  );

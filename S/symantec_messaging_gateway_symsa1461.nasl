#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117614);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-12242", "CVE-2018-12243");
  script_bugtraq_id(105329, 105330);

  script_name(english:"Symantec Messaging Gateway 10.x < 10.6.6 Multiple Vulnerabilities (SYMSA1461)");
  script_summary(english:"Checks the Symantec Messaging Gateway version number.");

  script_set_attribute(attribute:"synopsis", value:
"A messaging security application running on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Symantec Messaging
Gateway (SMG) running on the remote host is 10.x prior to 10.6.6.
It is, therefore, affected by multiple vulnerabilities as described 
in the vendor advisory.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.symantec.com/en_US/article.SYMSA1461.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Messaging Gateway (SMG) version 10.6.6 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12242");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:messaging_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_messaging_gateway_detect.nasl");
  script_require_keys("www/sym_msg_gateway");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("vcf.inc");
include("http.inc");

appname = 'sym_msg_gateway';
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:443);
app_info = vcf::get_app_info(app:appname, port:port, webapp:true);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "10.0.0", "fixed_version" : "10.6.6"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

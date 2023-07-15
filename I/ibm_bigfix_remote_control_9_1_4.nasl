#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103188);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2016-2930");
  script_bugtraq_id(98304);

  script_name(english:"IBM BigFix Remote Control < 9.1.4 Authentication Bypass");
  script_summary(english:"Checks the version of IBM BigFix Remote Control.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by an
authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM BigFix Remote Control running on the remote host is
prior to 9.1.4. It is, therefore, affected by an authentication bypass
vulnerability that allows a remote attacker to perform administrative
actions without requiring authentication.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22002331");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM BigFix Remote Control version 9.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:bigfix_remote_control");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_remote_control");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_bigfix_remote_control.nbin");
  script_require_keys("installed_sw/IBM BigFix Remote Control");
  script_require_ports("Services/www", 80, 443, 9080, 9443);

  exit(0);
}

include("vcf.inc");
include("http.inc");

app = "IBM BigFix Remote Control";

constraints = [ { "min_version" : "9.0", "fixed_version" : "9.1.4" } ];

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:app, port:port, webapp:true);

vcf::check_granularity(app_info:app_info, sig_segments:2);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

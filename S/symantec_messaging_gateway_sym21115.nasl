
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169507);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2022-25629");
  script_xref(name:"IAVA", value:"2023-A-0007");

  script_name(english:"Symantec Messaging Gateway < 10.8 XSS (21115)");

  script_set_attribute(attribute:"synopsis", value:
"A messaging security application running on the remote host is affected by an XSS vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Symantec Messaging Gateway (SMG) running on the remote host is 
prior to 10.8. It is, therefore, affected by a cross-site scripting vulnerability where an authenticated user who has 
the privilege to add/edit annotations on the Content tab can craft a malicious annotation that can be executed on the 
annotations page.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/21115
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?104284a0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Messaging Gateway (SMG) version 10.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-25629");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:messaging_gateway");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_messaging_gateway_detect.nasl");
  script_require_keys("www/sym_msg_gateway");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var appname = 'sym_msg_gateway';
get_install_count(app_name:appname, exit_if_zero:TRUE);
var port = get_http_port(default:443);
var app_info = vcf::get_app_info(app:appname, port:port, webapp:true);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  {'fixed_version' : '10.8'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
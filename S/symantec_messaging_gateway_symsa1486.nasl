#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126780);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id("CVE-2019-12751");
  script_bugtraq_id(108925);

  script_name(english:"Symantec Messaging Gateway 10.x < 10.7.1 Privilege Escalation Vulnerability (SYMSA1486)");
  script_summary(english:"Checks the Symantec Messaging Gateway version number.");

  script_set_attribute(attribute:"synopsis", value:
"A messaging security application running on the remote host is
affected by an information disclosure vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Symantec Messaging
Gateway (SMG) running on the remote host is 10.x prior to 10.7.1.
It is, therefore, affected by a privilege escalation vulnerability as 
described in the vendor advisory. An authenticated attacker can exploit this
to gain privileged or administrator access to the system.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://support.symantec.com/us/en/article.SYMSA1486.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2615ec65");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Messaging Gateway (SMG) version 10.7.1 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12751");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:messaging_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_messaging_gateway_detect.nasl");
  script_require_keys("www/sym_msg_gateway");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

appname = 'sym_msg_gateway';
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:443);
app_info = vcf::get_app_info(app:appname, port:port, webapp:true);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '10.0.0', 'fixed_version' : '10.7.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

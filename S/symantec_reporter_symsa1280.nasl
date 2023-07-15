#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125357);
  script_version("1.3");
  script_cvs_date("Date: 2019/10/31 15:18:51");

  script_cve_id("CVE-2011-1473");

  script_name(english:"Symantec (Blue Coat) Reporter Denial of Service vulnerability (SYMSA1280)");
  script_summary(english:"Checks the version of Symantec Reporter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a version of Symantec (Blue Coat)
Reporter that is affected by a Denial of Service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Symantec
(formerly Blue Coat) Reporter installation running on the remote
host is prior to 10.3.1.1. It is, therefore,  is affected by a
denial of service vulnerability. The SSL/TLS implementation on
the remote host allows clients to renegotiate connections. The
computational requirements forrenegotiating a connection are
asymmetrical between the client and the server, with the server
performing several times more work. Since the remote host does not
appear to limit the number of renegotiations for a single
TLS / SSL connection, this permits a client to open several
simultaneous connections and repeatedly renegotiate them,
possibly leading to a denial of service condition.

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version
number.");
  # https://support.symantec.com/en_US/article.SYMSA1280.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ec34e39");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Reporter version 10.3.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-1473");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:reporter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_reporter_web_detection.nbin");
  script_require_keys("installed_sw/Symantec Reporter");
  script_require_ports("Services/www");

  exit(0);
}

include("http.inc");
include("vcf.inc");

port = get_http_port(default:8082);

app = "Symantec Reporter";

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:4);

constraints = [{"fixed_version" : "10.3.1.1" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118710);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-8715");

  script_name(english:"Appweb < 7.0.3 authCondition Authentication Bypass Vulnerability");
  script_summary(english:"Checks version in Server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server may be affected by a authentication bypass 
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Appweb installed on the
remote host is prior to 7.0.3. It is, therefore, have a logic flaw
related to the authCondition function in http/httpLib.c. With a 
forged HTTP request, it is possible to bypass authentication for the
form and digest login types.

Note that Nessus did not actually test for this issue, but instead 
has relied on the version in the server's banner.");
  # https://github.com/embedthis/appweb/issues/610
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2bbda6c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Appweb version 7.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8715");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mbedthis_software:mbedthis_appweb_http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("appweb_server_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/appweb");
  script_require_ports("Services/www", 80, 7777);

  exit(0);
}

include("vcf.inc");
include("audit.inc");
include("http.inc");

port = get_http_port(default:80);

# Make sure this is Appweb.
get_kb_item_or_exit('www/'+port+'/appweb');

app_info = vcf::get_app_info(app:"Appweb", kb_ver:'www/appweb/'+port+'/version', service:FALSE);

constraints = [{ "min_version" : "4.0", "fixed_version" : "7.0.3"  }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE);

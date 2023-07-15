#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106627);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id("CVE-2015-3200");
  script_bugtraq_id(74813);

  script_name(english:"lighttpd < 1.4.36 Multiple Vulnerabilities");
  script_summary(english:"Checks version in Server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a log injection vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of lighttpd running on the remote
host is prior to 1.4.36. It is, therefore, affected by the following
vulnerabilities :

  - mod_auth in lighttpd before 1.4.36 allows remote attackers
    to inject arbitrary log entries via a basic HTTP authentication
    string without a colon character, as demonstrated by a string
    containing a NULL and new line character.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://jaanuskp.blogspot.in/2015/05/cve-2015-3200.html");
  script_set_attribute(attribute:"see_also", value:"https://www.lighttpd.net/2015/7/26/1.4.36/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to lighttpd version 1.4.36 or later. Alternatively, apply the
vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lighttpd:lighttpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("lighttpd_detect.nasl");
  script_require_keys("installed_sw/lighttpd", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

appname = "lighttpd";
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:80);
app_info = vcf::get_app_info(app:appname, port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [{"fixed_version":"1.4.36"}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

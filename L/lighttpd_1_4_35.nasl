#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73123);
  script_version("1.10");
  script_cvs_date("Date: 2018/07/12 19:01:16");

  script_cve_id("CVE-2014-2323", "CVE-2014-2324");
  script_bugtraq_id(66153, 66157);

  script_name(english:"lighttpd < 1.4.35 Multiple Vulnerabilities");
  script_summary(english:"Checks version in Server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of lighttpd running on the remote
host is prior to 1.4.35. It is, therefore, affected by the following
vulnerabilities :

  - A SQL injection flaw exists in the 'mod_mysql_vhost'
    module where user input passed using the hostname is not
    properly sanitized. A remote attacker can exploit this
    to inject or manipulate SQL queries, resulting in the
    manipulation or disclosure of data. (CVE-2014-2323)

  - A traverse outside of restricted path flaw exists with
    the 'mod_evhost' and 'mod_simple_vhost' modules where
    user input passed using the hostname is not properly
    sanitized. A remote attacker can exploit this to gain
    access to potentially sensitive data. (CVE-2014-2324)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.lighttpd.net/2014/3/12/1.4.35/");
  # https://web.archive.org/web/20140829152551/http://redmine.lighttpd.net/projects/lighttpd/repository/revisions/2959
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08be46ff");
  script_set_attribute(attribute:"see_also", value:"http://download.lighttpd.net/lighttpd/security/lighttpd_sa_2014_01.txt");
  # http://download.lighttpd.net/lighttpd/security/lighttpd-1.4.34_fix_mysql_injection.patch
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c57451b6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to lighttpd version 1.4.35. Alternatively, apply the
vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");


  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lighttpd:lighttpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

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

constraints = [{"fixed_version":"1.4.35"}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{sqli:TRUE});

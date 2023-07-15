#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(17694);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/22");

  script_cve_id("CVE-2006-4110");
  script_bugtraq_id(19447);

  script_name(english:"Apache on Windows mod_alias URL Validation Canonicalization CGI Source Information Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
issue.");
 script_set_attribute(attribute:"description", value:
"The version of Apache running on the remote Windows host can be
tricked into disclosing the source of its CGI scripts because of a
configuration issue.  Specifically, if the CGI directory is located
within the document root, then requests that alter the case of the
directory name will bypass the mod_cgi cgi-script handler and be
treated as requests for ordinary files.");
 script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/442882/30/0/threaded");
 script_set_attribute(attribute:"solution", value:
"Reconfigure Apache so that the scripts directory is located outside
of the document root.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-4110");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");
 script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/09");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2021 Tenable Network Security, Inc.");

  script_dependencies("apache_http_version.nasl");
  script_require_keys("installed_sw/Apache", "Settings/PCI_DSS");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('install_func.inc');

if (!get_kb_item('Settings/PCI_DSS')) exit(0, 'PCI-DSS compliance checking is not enabled.');

get_install_count(app_name:'Apache', exit_if_zero:TRUE);
var port = get_http_port(default:80);
var install = get_single_install(app_name:'Apache', port:port, exit_if_unknown_ver:TRUE);

var source = get_kb_item_or_exit('www/apache/'+port+'/pristine/source', exit_code:1);
var version = get_kb_item_or_exit('www/apache/'+port+'/pristine/version', exit_code:1);

# Only Apache on Windows is Vuln
var regexes = "\((ALT Linux.+|CentOS|Darwin|Debian.*|Fedora|FreeBSD|Mac OS X.*|Linux/SuSE|Mageia|Mandr(ake|iva).+" +
              "|NETWARE|OpenBSD|OpenVMS|OS/2|Red Hat.*|.*RedHat|SuSE.+|Trustix.*|TurboLinux|UnitedLinux|Unix)\)";

if (preg(pattern:regexes, string:source)) 
  exit(0, 'The Apache install listening on port '+port+' is not running under Windows.');

var report =
  '\n  Version source    : ' + source +
  '\n  Installed version : ' + version +
  '\n';
security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);

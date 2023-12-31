#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17692);
  script_version("1.14");
  script_cvs_date("Date: 2018/11/15 20:50:25");

  script_cve_id("CVE-2008-0455", "CVE-2008-0456");
  script_bugtraq_id(27409);

  script_name(english:"Apache mod_negotiation Multi-Line Filename Upload Vulnerabilities");
  script_summary(english:"Checks version in Server response header");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server may be affected by one or more issues.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache running on the remote
host does not properly escape filenames in 406 responses. A remote
attacker can exploit this to inject arbitrary HTTP headers or conduct
cross-site scripting attacks by uploading a file with a specially
crafted name. 

Note that the remote web server may not actually be affected by these
vulnerabilities as Nessus has relied solely on the version number in
the server's banner.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/486847/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=46837");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?164dd6e5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache 2.3.2 or later. Alternatively, apply the workaround
referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2018 Tenable Network Security, Inc.");

  script_dependencies("apache_http_version.nasl");
  script_require_keys("installed_sw/Apache", "Settings/PCI_DSS");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("install_func.inc");

# Only PCI considers this an issue.
if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

get_install_count(app_name:"Apache", exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:"Apache", port:port, exit_if_unknown_ver:TRUE);

# Check if we could get a version first, then check if it was
# backported
version = get_kb_item_or_exit('www/apache/'+port+'/version', exit_code:1);
backported = get_kb_item_or_exit('www/apache/'+port+'/backported', exit_code:1);

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "Apache");
source = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);

if (version =~ '^2(\\.3)?$') exit(1, 'The banner from the Apache server listening on port '+port+' - '+source+' - is not granular enough to make a determination.');
if (version !~ "^\d+(\.\d+)*$") exit(1, "The version of Apache listening on port " + port + " - " + version + " - is non-numeric and, therefore, cannot be used to make a determination.");
if (
  version =~ '^(1\\.|2\\.([0-2][^0-9]))' ||
  (version =~ '^2\\.3[^0-9]' && ver_compare(ver:version, fix:'2.3.2') == -1)
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 2.3.2\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, install["version"]);

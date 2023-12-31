#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14803);
 script_cvs_date("Date: 2018/06/29 12:01:03");
 script_version("1.26");

 script_cve_id("CVE-2004-0811");
 script_bugtraq_id(11239);
 script_xref(name:"Secunia", value:"12633");
 script_xref(name:"Secunia", value:"12641");
 script_xref(name:"Secunia", value:"13025");

 script_name(english:"Apache <= 2.0.51 Satisfy Directive Access Control Bypass");
 script_summary(english:"Checks for version of Apache");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an access control bypass
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Apache web server 2.0.51. It is reported
that this version of Apache is vulnerable to an access control bypass
attack. This issue occurs when using the 'Satisfy' directive. An
attacker may gain unauthorized access to restricted resources if
access control relies on this directive.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache web server 2.0.52 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/23");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2018 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("apache_http_version.nasl");
 script_require_keys("installed_sw/Apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

if ( get_kb_item("CVE-2004-0811") ) exit(0);

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("webapp_func.inc");

get_install_count(app_name:"Apache", exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:"Apache", port:port, exit_if_unknown_ver:TRUE);

# Check if we could get a version first, then check if it was
# backported
version = get_kb_item_or_exit('www/apache/'+port+'/version', exit_code:1);
backported = get_kb_item_or_exit('www/apache/'+port+'/backported', exit_code:1);

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "Apache");
source = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);

# Check if the version looks like either ServerTokens Major/Minor
# was used
if (version =~ '^2(\\.0)?$') exit(1, "The banner from the Apache server listening on port "+port+" - "+source+" - is not granular enough to make a determination.");
if (version !~ "^\d+(\.\d+)*$") exit(1, "The version of Apache listening on port " + port + " - " + version + " - is non-numeric and, therefore, cannot be used to make a determination.");
if (version =~ '^2\\.0' && ver_compare(ver:version, fix:'2.0.52') == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.0.52\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, install["version"]);

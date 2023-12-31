#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14748);
 script_cvs_date("Date: 2018/11/15 20:50:25");
 script_version("1.30");

 script_cve_id("CVE-2004-0747", "CVE-2004-0748", "CVE-2004-0751", "CVE-2004-0786", "CVE-2004-0809");
 script_bugtraq_id(11185, 11187);

 script_name(english:"Apache 2.0.x < 2.0.51 Multiple Vulnerabilities (OF, DoS)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its Server response header, the remote host is running a
version of Apache 2.0.x prior to 2.0.51. It is, therefore, affected by
multiple vulnerabilities :

  - An input validation issue in apr-util can be triggered
    by malformed IPv6 literal addresses and result in a 
    buffer overflow (CVE-2004-0786).

  - There is a buffer overflow that can be triggered when
    expanding environment variables during configuration
    file parsing (CVE-2004-0747).

  - A segfault in mod_dav_ds when handling an indirect lock
    refresh can lead to a process crash (CVE-2004-0809).

  - A segfault in the SSL input filter can be triggered
    if using 'speculative' mode by, for instance, a proxy
    request to an SSL server (CVE-2004-0751).

  - There is the potential for an infinite loop in mod_ssl
    (CVE-2004-0748)." );
 script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=31183" );
 script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.0" );
 script_set_attribute(attribute:"solution", value:"Upgrade to Apache 2.0.51 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/08");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
script_end_attributes();

 
 summary["english"] = "Checks version of Apache";
 
 script_summary(english:summary["english"]);
 
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
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("install_func.inc");

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
if (version =~ '^2\\.0' && ver_compare(ver:version, fix:'2.0.51') == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.0.51\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, install["version"]);

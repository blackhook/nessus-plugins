#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11793);
 script_version("1.32");
 script_cvs_date("Date: 2018/06/29 12:01:03");

 script_bugtraq_id(8226);
 script_cve_id("CVE-2003-0460");
 
 script_name(english:"Apache < 1.3.28 Multiple Vulnerabilities (DoS, ID)");
 script_summary(english:"Checks for version of Apache");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of
Apache which is older than 1.3.28

There are several flaws in this version, including a denial of service
in redirect handling, a denial of service with control character 
handling in the 'rotatelogs' utility and a file descriptor leak in 
third-party module handling.

*** Note that Nessus solely relied on the version number
*** of the remote server to issue this warning. This might
*** be a false positive" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.3.28" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"see_also", value:"http://www.apache.org/dist/httpd/Announcement.html" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/07/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/07/18");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2003-2018 Tenable Network Security, Inc.");
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
install = get_single_install(app_name:"Apache", port:port);

# Check if we could get a version first,  then check if it was
# backported
version = get_kb_item_or_exit('www/apache/'+port+'/version', exit_code:1);
backported = get_kb_item_or_exit('www/apache/'+port+'/backported', exit_code:1);

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "Apache");
source = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);

# Check if the version looks like either ServerTokesn Major/Minor
# was used

if (version =~ '^1(\\.3)?$') exit(1, "The banner from the Apache server listening on port "+port+" - "+source+" - is not granular enough to make a determination.");
if (version !~ "^\d+(\.\d+)*$") exit(1, "The version of Apache listening on port " + port + " - " + version + " - is non-numeric and, therefore, cannot be used to make a determination.");
if (version =~ '^1\\.3' && ver_compare(ver:version, fix:'1.3.28') == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.3.28\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, install["version"]);

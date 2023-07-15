#
# (C) Tenable Network Security, Inc.
#

#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>,
# with the impulsion of H D Moore on the Nessus Plugins-Writers list
#


include("compat.inc");

if(description)
{
 script_id(10918);
 script_version("1.31");
 script_bugtraq_id(4189);
 script_cve_id("CVE-2002-0082");
 
 script_name(english:"Apache-SSL < 1.3.23+1.46 i2d_SSL_SESSION Function SSL Client Certificate Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is using a version of Apache-SSL that is older than
1.3.22+1.46.  Such versions are vulnerable to a buffer overflow that,
albeit difficult to exploit, may allow an attacker to execute
arbitrary commands on this host subject to the privileges under which
the web server operates." );
 script_set_attribute(attribute:"see_also", value:"http://www.apache-ssl.org/advisory-20020301.txt" );
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2002/Feb/376" );
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2002/Mar/64" );
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2002/Mar/76" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache-SSL version 1.3.23+1.47 or later. [Note that the
vulnerability was initially addressed in 1.3.23+1.46 but that version
had a bug.]");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/03/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/02/27");
 script_cvs_date("Date: 2018/11/15 20:50:25");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:apache-ssl:apache-ssl");
script_end_attributes();

 
 summary["english"] = "Checks for version of Apache-SSL";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2018 Tenable Network Security, Inc.");
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
banner = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);
 
server = strstr(banner, "Server:");
server = server - strstr(server, '\r\n');
if (" Ben-SSL/" >< server)
{
  ver = NULL;

  pat = "^Server:.*Apache(-AdvancedExtranetServer)?/.* Ben-SSL/([0-9]+\.[0-9]+)";
  item = pregmatch(pattern:pat, string:server);
  if (!isnull(item)) ver = item[2];

  if (!isnull(ver) && ver =~ "^1\.([0-9]($|[^0-9])|([0-3][0-9]|4[0-5])($|[^0-9]))")
  {
    report = string(
      "\n",
      "The remote Apache-SSL server uses the following Server response\n",
      "header :\n",
      "\n",
      "  ", server, "\n"
    );
    security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
    exit(0);
  }
}

audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, install["version"]);


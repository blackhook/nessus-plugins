#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(12046);
 script_version("1.25");
 script_cvs_date("Date: 2018/11/15 20:50:25");

 script_cve_id("CVE-2004-0009");
 script_bugtraq_id(9590);
 script_xref(name:"Secunia", value:"10811");
 
 script_name(english:"Apache-SSL SSLVerifyClient SSLFakeBasicAuth Client Certificate Forgery");
 script_summary(english:"Checks for version of Apache-SSL");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a client certificate forging
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of ApacheSSL that is older than
1.3.29/1.53. Such versions are reportedly vulnerable to a flaw that
could allow an attacker to make the remote server forge a client
certificate." );
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2004/Feb/294" );
 script_set_attribute(attribute:"see_also", value:"http://www.apache-ssl.org/advisory-20040206.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ApacheSSL 1.3.29/1.53 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/02/06");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:apache-ssl:apache-ssl:1.3.28_1.52 and previous versions");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");
 
 script_copyright(english:"This script is Copyright (C) 2004-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("apache_http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("installed_sw/Apache");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

get_install_count(app_name:"Apache", exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:"Apache", port:port, exit_if_unknown_ver:TRUE);
banner = get_kb_item_or_exit('www/apache/'+port+'/source', exit_code:1);
 
serv = strstr(banner, "Server");
if(preg(pattern:".*Apache(-AdvancedExtranetServer)?/.* Ben-SSL/1\.([0-9][^0-9]|[0-4][0-9]|5[0-2])[^0-9]", string:serv))
{
  security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Apache", port, install["version"]);

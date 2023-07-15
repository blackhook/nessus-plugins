#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
  script_id(11636);
  script_version("1.23");
  script_cve_id("CVE-2003-1458", "CVE-2003-1459");
  script_bugtraq_id(7542, 7543, 7625);

  script_name(english:"ttCMS 2.2 Multiple Vulnerabilities");
  script_summary(english: "Attempts to include a file");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a PHP script that is affected by multiple
vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"The remote server is running a version of ttCMS that is prone to code
injection as well as SQL injection attacks. 

An attacker may use these flaws to execute arbitrary PHP code on this
host or to take the control of the remote database." );
  script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of ttCMS." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2003-1458");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(89, 94);

  script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english: "CGI abuses");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");   

function check(port, dir)
{
 local_var  r;
 if(isnull(dir))dir = "";
 set_http_cookie(name: "ttcms_user_admin", value: "1");
 r = http_send_recv3(method: "GET", item:dir+"/admin/templates/header.php?admin_root=http://example.com", port:port);
 if (isnull(r)) return(0);
 
 if("http://example.com/templates/header.inc.php" >< r[2])
 {
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  exit(0);
 }
}

    
    
port = get_http_port(default:80);

if (! can_host_php(port:port) ) exit(0);

 foreach dir (cgi_dirs())
 {
  check(port:port, dir:dir);
 }

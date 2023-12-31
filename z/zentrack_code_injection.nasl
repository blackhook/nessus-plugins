#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

#
# Ref:
#
# Date: 6 Jun 2003 01:00:55 -0000
# From: <farking@i-ownur.info>
# To: bugtraq@securityfocus.com
# Subject: zenTrack Remote Command Execution Vulnerabilities



include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
  script_id(11702);
  script_version("1.27");

  script_bugtraq_id(7843);

  script_name(english:"zenTrack index.php Multiple Parameter Remote File Inclusion");
  script_summary(english:"Checks for the presence of zenTrack's index.php");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
remote file include attacks." );
  script_set_attribute(attribute:"description", value:
"It is possible to make the remote host include php files hosted on a
third-party server using the version of zenTrack installed on the
remote host. 

An attacker may use this flaw to inject arbitrary code and to gain a
shell with the privileges of the web server on the affected host." );
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/324214/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/forum/forum.php?forum_id=283172" );
  script_set_attribute(attribute:"solution", value:"Upgrade to zenTrack 2.4.2 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"No CVE available for this vulnerability.");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/06");
  script_set_attribute(attribute:"vuln_publication_date", value: "2003/06/06");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2003-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CGI abuses");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);



function check(loc)
{
 local_var r, req;
 r = http_send_recv3(method: "GET", item:string(loc, "/index.php?libDir=http://example.com"),
 		port:port);			
 if( r == NULL )exit(0);
 if("http://example.com/configVars.php" >< r[2])
 {
 	security_hole(port);
	exit(0);
 }
}



foreach dir (cgi_dirs())
{
 check(loc:dir);
}

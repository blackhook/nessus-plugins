#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Ref:
#
# From: "Frog Man" <leseulfrog@hotmail.com>
# To: bugtraq@securityfocus.com
# Cc: vulnwatch@vulnwatch.org
# Date: Mon, 03 Mar 2003 13:57:43 +0100
# Message-ID: <F33JEyTeTaj1qNIFR2e000195ec@hotmail.com>
# Subject: [VulnWatch] WebChat (PHP)


include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
  script_id(11315);
  script_version("1.25");
  script_cve_id("CVE-2007-0485");
  script_bugtraq_id(7000);

  script_name(english:"WebChat defines.php WEBCHATPATH Parameter Remote File Inclusion");
  script_summary(english:"Checks for the presence of Webchat's defines.php");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
remote code inclusion flaw." );
  script_set_attribute(attribute:"description", value:
"The version of Webchat installed on the remote host allows an attacker
to read local files or execute PHP code, possibly taken from third-
party sites, subject to the permissions of the web server user id." );
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/313606" );
  script_set_attribute(attribute:"solution", value:"Contact the vendor for a patch or remove the application." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-0485");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/03");
  script_set_attribute(attribute:"vuln_publication_date", value: "2007/01/21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2003-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CGI abuses");

  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
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
 local_var r, w;

 w = http_send_recv3(method:"GET", port: port, item:string(loc, "/defines.php?WEBCHATPATH=http://example.com/"));
 if (isnull(w)) exit(0);
 r = w[2];
 if("http://example.com/db_mysql.php" >< r )
 {
 	security_hole(port);
	exit(0);
 }
}


foreach dir (dirs)
{
 check(loc:dir);
}

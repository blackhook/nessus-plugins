#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Ref:
#
# Date: Thu, 22 May 2003 14:42:13 +0400
# From: Over_G <overg@mail.ru>
# To: bugtraq@securityfocus.com
# Subject: PHP source code injection in BLNews


include('deprecated_nasl_level.inc');
include('compat.inc');


if(description)
{
  script_id(11647);
  script_bugtraq_id(7677);
  script_cve_id("CVE-2003-0394");
  script_version("1.29");
  script_xref(name:"Secunia", value:"8864");

  script_name(english:"BLNews objects.inc.php4 Server[path] Parameter Remote File Inclusion");
  script_summary(english:"Checks for the presence of objects.inc.php4");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application has a remote code execution vulnerability." );
  script_set_attribute( attribute:"description", value:
"It is possible to make the remote host include remote PHP files
using the BLnews CGI suite.

A remote attacker may exploit this to execute arbitrary code with
the privileges of the web server." );

  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=105379530927567&w=2");

  script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of BLNews.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:W/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2003-0394");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/27");
  script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2003-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencie("find_service1.nasl", "http_version.nasl");
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
if(!can_host_php(port:port)) exit(0);



function check(loc)
{
 local_var r, w;
 w = http_send_recv3(item:string(loc, "/admin/objects.inc.php4?Server[path]=http://example.com&Server[language_file]=nessus.php"),
 		method:"GET", port:port);			
 if (isnull(w)) exit(0);
 r = strcat(w[0], w[1], '\r\n', w[2]);
 if(egrep(pattern:".*http://example.com/admin/nessus\.php", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}



dirs = make_list(cgi_dirs());


foreach dir (dirs)
{
 check(loc:dir);
}

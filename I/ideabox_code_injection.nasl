#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Ref:
#
# Date: Tue, 29 Apr 2003 15:06:43 +0400 (MSD)
# From: "euronymous" <just-a-user@yandex.ru>
# To: bugtraq@securityfocus.com
# Subject: IdeaBox: Remote Command Execution


include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
  script_id(11557);
  script_version("1.24");

  script_bugtraq_id(7488);

  script_name(english:"IdeaBox include.php ideaDir Parameter Remote File Inclusion");
  script_summary(english:"Injects a path");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP script that is affected by a
remote file inclusion vulnerability." );
  script_set_attribute(attribute:"description", value:
"It is possible to make the remote host include PHP files hosted
on a third-party server using ideabox.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server." );
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2003/Apr/367" );
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:U/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"No CVE available for this vulnerability.");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2003-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CGI abuses");
  
  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

#
# The script code starts here
#


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

function check(loc)
{
 local_var res;
 res = http_send_recv3(method:"GET", item:string(loc,"/include.php?ideaDir=http://example.com"), port:port);
 if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

 if (egrep(pattern:".*http://example.com/user\.php", string:res[2]))
 {
   security_hole(port:port);
   exit(0);
 }
}

dir = make_list(cgi_dirs());
dirs = make_list();
foreach d (dir)
  dirs = make_list(dirs, string(d, "/ideabox"));

dirs = make_list(dirs, "", "/ideabox");



foreach dir (dirs)
{
 check(loc:dir);
}

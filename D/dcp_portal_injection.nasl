#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# DCP-Portal Cross Site Scripting Bugs
#
# From: "Frog Man" <leseulfrog@hotmail.com>
# To: bugtraq@securityfocus.com
# Subject: DCP-Portal (PHP)


include('deprecated_nasl_level.inc');
include('compat.inc');


if (description)
{
  script_id(11476);
  script_version("1.25");
  script_bugtraq_id(6525);
 
  script_xref(name:"Secunia", value:"7834");

  script_name(english:"DCP-Portal lib.php root Parameter Remote File Inclusion");
  script_summary(english:"Determine if DCP-Portal is vulnerable to an injection attack");

  script_set_attribute( attribute:"synopsis", value:
"An application running on the remote web server has a remote file
include vulnerability." );
  script_set_attribute( attribute:"description",  value:
"DCP-Portal has a remote file include vulnerability.  A remote
attacker could exploit this to execute arbitrary PHP code in the
context of the web server." );
  script_set_attribute(attribute:"see_also",value:"https://www.securityfocus.com/archive/1/305358");
  script_set_attribute( attribute:"solution",  value:
"There is no known solution at this time.  It appears this application
has not been actively maintained for several years." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:U/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"No CVE available for this vulnerability.");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/26");
  script_set_attribute(attribute:"vuln_publication_date", value: "2003/01/04");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2003-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

if(!can_host_php(port:port))exit(0);

foreach d (cgi_dirs())
{
 url = string(d, "/library/lib.php?root=http://example.com");
 buf = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(buf)) exit(0);
 
 if ("http://example.com/lib_nav.php" >< buf[2])
 {
   security_hole(port);
   exit(0);
 }
}


#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
  script_id(16180);
  script_version("1.19");

  script_bugtraq_id(12284); 
  script_xref(name:"Secunia", value:"13896");

  script_name(english:"SiteMinder smpwservicescgi.exe Arbitrary Site Redirect");
  script_summary(english:"Checks for a flaw in SiteMinder");
 
  script_set_attribute(
  attribute:"synopsis",
  value:"The remote web server is affected by a redirection weakness."
 );
  script_set_attribute(attribute:"description", value:
"The remote host is running Netegrity SiteMinder, an access management
solution. 

The remote version of this software is vulnerable to a page injection
flaw that may allow an attacker to trick users into sending him their
credentials via a link to the 'smpwservicescgi.exe' program with a
rogue TARGET argument value which will redirect them to an arbitrary
website after they authenticate to the remote service.");
  # http://www.scip.ch/cgi-bin/smss/showadv.pl?id=1022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30124009");
  # https://seclists.org/bugtraq/2005/Jan/205
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9834b14f");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"No CVE available for this vulnerability.");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/17");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2005-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  
  script_family(english:"CGI abuses");
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

foreach dir ( cgi_dirs() )
{
 w = http_send_recv3(method:"GET", port:port, item:dir + "/pwcgi/smpwservicescgi.exe?TARGET=http://www.example.com");
 if (isnull(w)) exit(1, "The web server did not answer");
 res = strcat(w[0], w[1], '\r\n', w[2]);
if ( '<input type=hidden name=TARGET value="http://www.example.com">' >< res &&
     '<form NAME="PWChange" METHOD="POST" ACTION="/siteminderagent/pwcgi/smpwservicescgi.exe">' >< res )
 {
	 security_warning(port);
	 exit(0);
 }
}

#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Ref: Dr_insane
#


include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
  script_id(14681);
  script_version("1.18");
  script_bugtraq_id(11111);
  
  script_name(english:"Keene Digital Media Server Multiple Script XSS");

 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to multiple cross-site scripting
attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host runs Keene digital media server, a web server used to
share digital information. 

This version is vulnerable to multiple cross-site scripting attacks." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/08");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks XSS in Keene server");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CGI abuses : XSS");
  script_require_ports("Services/www", 80);
  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

foreach u (make_list( "/dms/slideshow.kspx?source=<script>foo</script>",
	  	      "/dms/dlasx.kspx?shidx=<script>foo</script>", 
		      "/igen/?pg=dlasx.kspx&shidx=<script>foo</script>",
		      "/dms/mediashowplay.kspx?pic=<script>foo</script>&idx=0",
		      "/dms/mediashowplay.kspx?pic=0&idx=<script>foo</script>" ))
{
 v = split(u, sep: '?', keep: 0);
 if (test_cgi_xss(port: port, cgi: v[0], qs: v[1], dirs: make_list(""),
     pass_str: "<script>foo</script>") )
  break;
}

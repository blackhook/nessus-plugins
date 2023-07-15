#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Note: Based on the proof of concept example,  NOT fully tested
#
# Reference: http://www.example.com/modules.php?op=modload&name=Downloads&file=index&req=addrating&ratinglid=[DOWNLOAD ID]&ratinguser=[REMOTE USER]&ratinghost_name=[REMOTE HOST ;-)]&rating=[YOUR RANDOM CONTENT] 
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11676);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(7702);

  script_name(english:"PostNuke Rating System DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"The remote host is running PostNuke.  PostNuke Phoenix 0.721, 0.722
and 0.723 allows a remote attacker causes a denial of service to
legitmate users, by submitting a string to its rating system.");
  script_set_attribute(attribute:"solution", value:
"Add vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postnuke_software_foundation:postnuke");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2022 Tenable Network Security, Inc.");

  script_dependencies("postnuke_detect.nasl");
  script_require_keys("www/postnuke");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/postnuke" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
version = stuff[1];

if(ereg(pattern:"^0\.([0-6]\.|7\.([0-1]\.|2\.[0-3]))", string:version)) 
	security_warning(port);

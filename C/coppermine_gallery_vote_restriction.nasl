#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


include('deprecated_nasl_level.inc');
include('compat.inc');


if(description)
{
 script_id(15531);
 script_bugtraq_id(11485);
 script_version("1.13");

 script_name(english:"Coppermine Photo Gallery Voting Restriction Bypass");
 script_summary(english:"Does a version check");

 script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host has an access
restriction bypass vulnerability." );
 script_set_attribute( attribute:"description", value:
"The remote host is running Coppermine Gallery - a set of PHP scripts
designed to handle galleries of pictures.

This product has a vulnerability which allows a remote attacker with
cookies disabled to cast multiple votes for a picture." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?250c8484"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Coppermine 1.3.3 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/12");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
 script_dependencie("coppermine_gallery_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

kb = get_kb_list("www/" + port + "/coppermine_photo_gallery");
if ( isnull(kb) ) exit(0);

foreach k ( kb )
{
 version = split(k, sep:" under ", keep:0);
 if ( ereg(pattern:"^v?(0\.|1\.(0\.|1 (devel|Beta [12])|[0-2]\.|3\.[0-2]))", string:version[0], icase:TRUE) )
 	{
	security_warning(port);
	exit(0);
	}
}


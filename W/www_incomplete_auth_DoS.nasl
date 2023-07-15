##
#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2021/09/13. Deprecated by RES-74695. 
##

include("compat.inc");

if(description)
{
 script_id(12200);
 script_version("1.14");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/14");

 script_name(english:"Web Server Incomplete Basic Authentication DoS (deprecated)");
 
 script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated." );
 script_set_attribute(attribute:"description", value:
"This plugin is no longer relevant, and may never have worked correctly." );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/04/11");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Basic authentication without password chokes the web server");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencies("http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

exit(0, 'This plugin has been deprecated.');

 

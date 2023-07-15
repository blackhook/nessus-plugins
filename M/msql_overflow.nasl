#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2020/12/02. Deprecated due to age of the vulnerability an unreliability of the plugin.


include("compat.inc");

if(description)
{
 script_id(10143);
 script_version("1.39");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/03");

 script_cve_id("CVE-1999-0753");
 script_bugtraq_id(591);

 script_name(english:"Mini SQL w3-msql Arbitrary Directory Access (deprecated)");
 
 script_set_attribute(attribute:"synopsis", value:
"This plugin as been deprecated." );
 script_set_attribute(attribute:"description", value:
"This plugin has been deprecated due to the age of the vulnerability and unreliability of the plugin." );
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/1999/Aug/185" );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0753");
	
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/09/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/08/18");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 1999-2020 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

exit(0, "This plugin has been deprecated.");

#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2020/03/25.

include('compat.inc');

if (description)
{
 script_id(11555);
 script_version("1.23");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/27");
 script_bugtraq_id(7397);
 script_name(english:"AN HTTPd count.pl Traversal Arbitrary File Overwrite (deprecated)");
 script_summary(english:"Creates a file on the remote server");

 script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
 script_set_attribute(attribute:"description", value:
"The remote web server is running a CGI called 'count.pl' which is
affected by an directory traversal vulnerability. An attacker could
exploit this in order to overwrite any existing file on the remote
server, with the privileges of the httpd server.

This plugin has been deprecated as it resulted in false positives without reliable detecting the vulnerability on the
intended target. AN HTTPd has not been available to download for several years and the website no longer exists.");
 script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/319354/30/0/threaded");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"This vulnerability could be used to overwrite any existing file on the remote server.");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/04/27");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_end_attributes();

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2003-2020 Tenable Network Security, Inc.");

 script_family(english:"CGI abuses");

 script_dependencies("find_service1.nasl", "http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);
 exit(0);
}

exit(0, "This plugin has been deprecated.");

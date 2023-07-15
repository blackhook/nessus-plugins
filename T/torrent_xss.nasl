#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
 script_id(15924);
 script_version("1.21");
 script_bugtraq_id(11839);

 script_name(english:"Blog Torrent < 0.81 btdownload.php Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has a application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"There is a remote directory traversal vulnerability in
Blog Torrent, a web-based application that allows users
to host files for Bit Torrents.

There is a cross-site scripting issue in the remote
version of this software that may allow an attacker to set
up attacks against third parties by using the remote server." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BlogTorrent 0.81." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/02");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_summary(english:"Looks for a XSS in Blog Torrent.");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP", "Settings/ParanoidReport");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, php: 1, no_xss: 1);

test_cgi_xss( port: port, cgi: "/btdownload.php", 
	      pass_str: "<script>foo</script>", 
	      qs: "type=torrent&file=<script>foo</script>" );

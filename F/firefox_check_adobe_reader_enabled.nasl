#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(66519);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Adobe Reader Enabled in Browser (Mozilla Firefox)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has Adobe Reader enabled for Mozilla Firefox.");
  script_set_attribute(attribute:"description", value:
"Adobe Reader is enabled in Mozilla Firefox.");
  script_set_attribute(attribute:"solution", value:
"Disable Adobe Reader unless it is needed.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:reader");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2022 Tenable Network Security, Inc.");

  script_dependencies("adobe_reader_enabled_in_browser.nasl");
  script_require_keys("SMB/Acroread/firefox_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Get a list of users that Adobe is still enabled for
users = get_kb_item_or_exit("SMB/Acroread/firefox_enabled");
users = str_replace(string:users, find:',', replace:'\n ');

port = get_kb_item('SMB/transport');
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\nAdobe Reader is enabled in Mozilla Firefox for the following users :' +
    '\n' +
    '  ' + users + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);

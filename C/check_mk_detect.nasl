#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59837);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/22");

  script_name(english:"Check_MK Agent Detection");
  script_summary(english:"Detects a Check_MK agent.");

  script_set_attribute(attribute:"synopsis", value:
"An IT monitoring service is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"Check_MK agent, an IT monitoring service, is running on the remote
host. Check_MK allows clients to retrieve large amounts of data about
the target.");
  script_set_attribute(attribute:"see_also", value:"https://mathias-kettner.com/");
  script_set_attribute(attribute:"solution", value:
"Make sure the use of this program is in accordance with your corporate
policy.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:check_mk_project:check_mk");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service.nasl");
  script_require_keys("Services/check_mk");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item_or_exit("Services/check_mk");
banner = get_kb_item_or_exit("check_mk/banner/" + port);

# Extract the version from the response.
matches = pregmatch(string:banner, pattern:"Version: ([\w.]+)");
if (!isnull(matches))
  ver = matches[1];

# Extract Agent OS type
matches = pregmatch(string:banner, pattern:"AgentOS: ([\w.]+)");
if(!isnull(matches))
  os = matches[1];

# Store our findings.
set_kb_item(name:"Check_MK/Installed", value:port);
set_kb_item(name:"Check_MK/" + port + "/Banner", value:banner);

if (ver)
  set_kb_item(name:"Check_MK/" + port + "/Version", value:ver);
if (os)
  set_kb_item(name:"Check_MK/" + port + "/AgentOS", value:os);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  if (ver)
  {
    report =
      '\n  Installed version : ' + ver +
      '\n';

    if (report_verbosity > 1)
    {
      bar = crap(data:"-", length:30);
      snip = bar + " snip " + bar;

      report +=
        '\nThe following information was provided by the remote service :' +
        '\n' +
        '\n  ' + snip;

      lines = split(banner, sep:'\n', keep:FALSE);
      for (i = 0; i < 20; i++)
      {
        report += '\n  ' + lines[i];
      }

      report +=
        '\n  ' + snip +
        '\n';
    }
  }
}

security_note(port:port, extra:report);

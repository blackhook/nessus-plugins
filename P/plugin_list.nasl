#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112154);
  script_version("1.4");
  script_cvs_date("Date: 2018/09/24 10:11:01");

  script_name(english:"Nessus Launched Plugin List");
  script_summary(english:"Lists the plugins IDs launched during a scan.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin displays information about the launched plugins.");
  script_set_attribute(attribute:"description", value:
"This plugin displays the list of launched plugins in a semicolon
delimited list.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/28");

  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_add_preference(name:"Enable Plugin List Report", type:"checkbox", value:"no");

  if ( !isnull(ACT_END2) ) script_category(ACT_END2);
  else script_category(ACT_END);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_exclude_keys("Host/dead");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

opt = script_get_preference("Enable Plugin List Report");
if (opt && opt == "no")
  exit(0, "The plugin list report preference was not enabled.");

if (get_kb_item("Host/dead")) exit(0, "The remote host was not responding.");

plugins = get_kb_list("Launched/*");
if (isnull(plugins)) exit(0, "No plugins launched during the scan.");

report = make_list();

foreach plugin (keys(plugins))
{
  match = pregmatch(pattern:"Launched/([0-9]+)", string:plugin);
  if (!isnull(match)) report = make_list(match[1], report);
}

report = join(report, sep:';');

security_report_v4(port:0, severity:SECURITY_NOTE, extra:report);

#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72367);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

  script_xref(name:"IAVT", value:"0001-T-0509");

  script_name(english:"Microsoft Internet Explorer Version Detection");
  script_summary(english:"Reports Microsoft Internet Explorer version");

  script_set_attribute(attribute:"synopsis", value:"Internet Explorer is installed on the remote host.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host contains Internet Explorer, a web browser
created by Microsoft."
  );
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/17621/internet-explorer-downloads");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/IE/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/IE/Version");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\n  Version  : ' + version + 
    '\n';
  security_note(port:port, extra:report);
}
else security_note(port);

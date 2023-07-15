#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72092);
  script_version("1.3");
  script_cvs_date("Date: 2018/11/15 20:50:26");

  script_name(english:"ColdFusion Extended Support Version Detection (credentialed check)");
  script_summary(english:"Checks if any ColdFusion installs require long-term support");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains one or more versions of ColdFusion that
require long-term support.");
  script_set_attribute(attribute:"description", value:
"According to its version, there is at least one installation of
ColdFusion that is potentially under Extended Support.

Note that the Extended Support program requires a vendor contract.
Extended Support provides upgrades and security fixes for two years
after regular support ends.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/support/programs/adobe-support-policies-supported-product-versions.html#sort-a");
  #https://helpx.adobe.com/support/programs/eol-matrix.html#63
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75eac050");
  script_set_attribute(attribute:"solution", value:
"Ensure that the host subscribes to Adobe's Extended Support program for
ColdFusion and continues to receive security updates.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_win_unsupported.nasl");
  script_require_keys("SMB/coldfusion/instance");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

info = "";

extended_support_installs = get_kb_list_or_exit("SMB/coldfusion/extended_support/*");

if (extended_support_installs)
{
  foreach path_ver (keys(extended_support_installs))
  {
    pv = path_ver - "SMB/coldfusion/extended_support/";
    pieces = split(pv, sep:"/", keep:FALSE);
    info += '\n' +
            '\n  Path          : ' + pieces[0] +
            '\n  Version       : ' + pieces[1] +
            '\n  Support dates : ' + extended_support_installs[path_ver];
  }
}

if (info)
  info = '\n' + 'The following ColdFusion installs are in Extended Support status : ' + info;

if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0) security_note(port:port, extra:info);
  else security_note(port);
}
else audit(AUDIT_NOT_INST, "ColdFusion under Extended Support");

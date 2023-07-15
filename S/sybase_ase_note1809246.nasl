#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70971);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_bugtraq_id(63549);
  script_xref(name:"IAVA", value:"2013-A-0217-S");

  script_name(english:"SAP Sybase Adaptive Server Enterprise Information Disclosure (SAP Note 1809246)");
  script_summary(english:"Checks sqlserver.exe version");

  script_set_attribute(attribute:"synopsis", value:
"The version of SAP Sybase Adaptive Server Enterprise (ASE) installed on
the remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"An unauthenticated, remote attacker can discover information relating
to the installed version of SAP Sybase ASE.  This information could be
used to allow the attacker to specialize further attacks against SAP
Sybase ASE.");
  script_set_attribute(attribute:"see_also", value:"https://service.sap.com/sap/support/notes/1809246");
  script_set_attribute(attribute:"see_also", value:"http://www.sybase.com/detail?id=1099371");
  script_set_attribute(attribute:"solution", value:"Apply one of the patches listed in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sybase:adaptive_server_enterprise");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sybase_ase_installed.nbin");
  script_require_keys("SMB/Sybase_ASE/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb = "SMB/Sybase_ASE/";
get_kb_item_or_exit(kb + "Installed");

path = get_kb_item_or_exit(kb + "Path");
ver  = get_kb_item_or_exit(kb + "Version");
ebf  = get_kb_item_or_exit(kb + "EBF");
arch = get_kb_item_or_exit(kb + "Architecture");
servername = get_kb_item(kb + "ServerName");
######################################################################
# This issue has been fixed in the following SAP Sybase ASE versions:
#
# Platform: Windows x64
#     EBF 21150: 15.7   SP100
#     EBF 20951: 15.7   ESD #4.2
#     EBF 21262: 15.5   ESD #5.3
#     EBF 21293: 15.0.3 ESD #4.3
#
# Platform: Windows x86
#     EBF 21149: 15.7   SP100
#     EBF 20950: 15.7   ESD #4.2
#     EBF 21261: 15.5   ESD #5.3
#     EBF 21286: 15.0.3 ESD #4.3
######################################################################

if (ver =~ "^15\.7([^0-9]|$)")
{
  # Choose the lowest EBF on this branch.
  ver_fix = "15.7 ESD #4.2";
  if (arch == "x64")
    ebf_fix = 20951;
  else
    ebf_fix = 20950;
}
else if (ver =~ "^15\.5([^0-9]|$)")
{
  # Choose the lowest EBF on this branch.
  ver_fix = "15.5 ESD #5.3";
  if (arch == "x64")
    ebf_fix = 21262;
  else
    ebf_fix = 21261;
}
else if (ver =~ "^15\.0\.3([^0-9]|$)")
{
  # Choose the lowest EBF on this branch.
  ver_fix = "15.0.3 ESD #4.3";
  if (arch == "x64")
    ebf_fix = 21293;
  else
    ebf_fix = 21286;
}

if (isnull(ebf_fix) || ebf >= ebf_fix)
  audit(AUDIT_INST_PATH_NOT_VULN, "SAP Sybase ASE", ver, path);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + ver_fix +
    '\n';
  if(servername)
  {
    servers = split(servername, keep:FALSE);
    foreach server (servers)
    {
      server_report += server + '\n' + crap(data:' ', length:22);
    }
    report += '  Server Name       : ' + server_report + '\n';
  }
}

port = get_kb_item("SMB/transport");
if (!port) port = 445;

security_warning(port:port, extra:report);
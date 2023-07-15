#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105300);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-17556");
  script_xref(name:"IAVA", value:"2017-A-0369");

  script_name(english:"Synaptics SynTP.sys Driver Keylogger Vulnerability");
  script_summary(english:"Checks version of SynTP.sys");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a kernel driver that is affected by a
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The 'SynTP.sys' driver included with Synaptics touch pad software
installed on the remote host is affected by a keylogger vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://support.hp.com/us-en/document/c05827409");
  script_set_attribute(attribute:"see_also", value:"https://www.synaptics.com/company/blog/touchpad-security-brief");
  script_set_attribute(attribute:"solution", value:
"Apply the vendor supplied patch appropriate to your environment.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-17556");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "Settings/ParanoidReport");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Grab the file version of the affected file.
winroot = hotfix_get_systemroot();
if (!winroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:winroot);
sys =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\drivers\SynTP.sys", string:winroot);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:sys,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

version = NULL;
pname = NULL;
if (!isnull(fh))
{
  ret = GetFileVersionEx(handle:fh);
  if (!isnull(ret)) children = ret['Children'];

  stringfileinfo = children['StringFileInfo'];
  if (!isnull(stringfileinfo))
  {
    foreach key (keys(stringfileinfo))
    {
      data = stringfileinfo[key];
      if (!isnull(data))
      {
        version  = data['FileVersion'];
        pname    = data['ProductName'];
      }
    }
  }
  CloseFile(handle:fh);
}
NetUseDel();

# remove potential excess data from FileVersion
# FileVersion actually returns Product Version
# e.g. '17.0.18.8 25Oct13'
version = split(version, sep:' ', keep:false);
version = version[0];

# Check the version number.
vuln = FALSE;
fix = '';
if (!isnull(version) && (!isnull(pname) && "Synaptics Pointing Device Driver" >< pname))
{
  if (version =~ "^19\.3\.31($|[^0-9])")
    fix = '19.3.31.31';
  else if (version =~ "^19\.3\.8($|[^0-9])")
    fix = "19.3.8.22";
  else if (version =~ "^19\.0\.19($|[^0-9])")
    fix = "19.0.19.63";
  else if (version =~ "^19\.0\.17($|[^0-9])")
    fix = "19.0.17.202";
  else if (version =~ "17\.0\.8($|[^0-9])")
    fix = "17.0.8.17";
  else if (version =~ "17\.0\.18($|[^0-9])")
    fix = "17.0.18.25";

  if (fix && ver_compare(ver:version, fix:fix) < 0)
    vuln = TRUE;
}
else
  audit(AUDIT_NOT_INST, "Synaptics Pointing Device Driver");

if (vuln)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port))
    port = 445;

  items = make_array("Path", winroot + "\System32\drivers\SynTP.sys",
                     "Installed version", version,
                     "Fixed version", fix);
  order = make_list("Path", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);
  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);

}
else
  audit(AUDIT_INST_VER_NOT_VULN, "Synaptics Pointing Device Driver");

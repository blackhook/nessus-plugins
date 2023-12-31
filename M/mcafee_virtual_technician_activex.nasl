#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(61719);
  script_version("1.6");
  script_cvs_date("Date: 2018/07/14  1:59:37");

  script_cve_id("CVE-2012-4598");
  script_bugtraq_id(53304);
  script_xref(name:"EDB-ID", value:"18805");
  script_xref(name:"EDB-ID", value:"18812");
  script_xref(name:"MCAFEE-SB", value:"SB10028");

  script_name(english:"McAfee Virtual Technician ActiveX Control GetObject() Method Remote Command Execution (SB10028)");
  script_summary(english:"Checks control's file version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An ActiveX control installed on the remote Windows host can be abused
to execute arbitrary code."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host has a version of the McAfee Virtual Technician
/ ePolicy Orchestrator ActiveX control that allows execution of
arbitrary code.  The 'GetObject()' method can be used to load any class
on the underlying operating system.  For example, by loading the
'WScript.Shell' class, attackers can then run arbitrary operating system
commands.

If an attacker can trick a user on the affected host into viewing a
specially crafted HTML document, he can leverage this issue to execute
arbitrary commands on the affected system subject to the user's
privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10028");
  script_set_attribute(
    attribute:"solution",
    value:"
Upgrade to McAfee Virtual Technician 6.4 / ePolicy Orchestrator 1.0.8 or
later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'McAfee Virtual Technician MVTControl 6.3.0.1911 GetObject Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:mcafee_virtual_technician");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_activex_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = 'SOFTWARE\\Classes\\MVT.MVTControl\\CLSID\\';

clsid = get_registry_value(handle:hklm, item:key);

RegCloseKey(handle:hklm);

close_registry();

if (isnull(clsid)) audit(AUDIT_NOT_INST, 'McAfee Virtual Technician');

if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");

info = '';

vuln_version = '6.3.0.1911';
fixed_version = '6.4';

file = activex_get_filename(clsid:clsid);

if (isnull(file))
{
  activex_end();
  exit(1, "activex_get_filename() returned NULL.");
}

if (!file)
{
  activex_end();
  audit(AUDIT_ACTIVEX_NOT_FOUND, clsid);
}

# Get its version.
version = activex_get_fileversion(clsid:clsid);
if (!version)
{
  activex_end();
  audit(AUDIT_VER_FAIL, file);
}

if(ver_compare(ver:version, fix:vuln_version) <= 0)
{
  if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
  {
      info += '\n  Class identifier  : ' + clsid +
              '\n  Filename          : ' + file +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : ' + fixed_version + '\n';
   }
}

activex_end();

# Report findings.
if (info)
{
  if (report_paranoia > 1)
  {
    report = info +
      '\n' +
      'Note, though, that Nessus did not check whether the kill bit was\n' +
      "set for the control's CLSID because of the Report Paranoia setting" + '\n' +
      'in effect when this scan was run.\n';
  }
  else
  {
    report = info +
      '\n' +
      'Moreover, its kill bit is not set so it is accessible via Internet\n' +
      'Explorer.\n';
  }

  if (report_verbosity > 0) security_hole(port:kb_smb_transport(), extra:report);
  else security_hole(kb_smb_transport());

  exit(0);
}
else
{
  if(ver_compare(ver:version, fix:vuln_version) > 0)
    audit(AUDIT_INST_VER_NOT_VULN, version, file);
  else
    exit(0, "The " + file + " control is installed, but its kill bit is set.");
}

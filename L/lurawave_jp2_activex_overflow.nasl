#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57939);
  script_version("1.5");
  script_cvs_date("Date: 2018/07/14  1:59:37");

  script_cve_id("CVE-2012-0977");
  script_bugtraq_id(51744);
  script_xref(name:"Secunia", value:"47350");

  script_name(english:"LuraWave JP2 ActiveX Control < 2.1.5.11 jp2_x.dll Remote Buffer Overflow");
  script_summary(english:"Checks the version of the control");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the LuraWave JP2 ActiveX control installed on the
remote Windows host reportedly contains a stack-based buffer overflow
vulnerability.  If an attacker can trick a user on the affected host
into viewing a specially crafted HTML document, he can leverage this
issue to execute arbitrary code on the affected system subject to the
user's privileges.");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.1.5.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:luratech:lurawave_jp2_activex_control");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_activex_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");

clsid = '{0D4B9606-1FEF-43B0-B76E-43150B060AEB}';

file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  exit(1, "activex_get_filename() returned NULL.");
}
if (!file)
{
  activex_end();
  exit(0, "The control is not installed since the class id '" + clsid + "' is not defined on the remote host.");
}

# Check if the single vulnerable version is installed.
ver = activex_get_fileversion(clsid:clsid);
if (ver && ver_compare(ver:ver, fix:"2.1.5.11", strict:FALSE) >= 0)
  exit(0, "The version " + ver + " install of the control ("+file+") is not affected.");

if (ver) ver = string("Version ", ver);
else ver = string("An unknown version");

report = NULL;
if (report_paranoia > 1)
{
  report = string(
    "\n",
    ver, " of the vulnerable control is installed as :\n",
    "\n",
    "  ", file, "\n",
    "\n",
    "Note, though, that Nessus did not check whether the kill bit was\n",
    "set for the control's CLSID because of the Report Paranoia setting\n",
    "in effect when this scan was run.\n"
  );
}
else if (activex_get_killbit(clsid:clsid) == 0)
{
  report = string(
    "\n",
    ver, " of the vulnerable control is installed as :\n",
    "\n",
    "  ", file, "\n",
    "\n",
    "Moreover, its kill bit is not set so it is accessible via Internet\n",
    "Explorer.\n"
  );
}

if (report)
{
  if (report_verbosity > 0) security_hole(port:kb_smb_transport(), extra:report);
  else security_hole(kb_smb_transport());
}

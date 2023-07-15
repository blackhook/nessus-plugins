#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(27599);
  script_version("1.29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/30");

  script_cve_id("CVE-2007-5660", "CVE-2007-6654");
  script_bugtraq_id(26280, 27013);

  script_name(english:"FLEXnet Connect Update Service ActiveX Control Multiple Code Execution Vulnerabilities");
  script_summary(english:"Checks version of Update Service ActiveX control");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that allows execution
of arbitrary code." );
  script_set_attribute(attribute:"description", value:
"Macrovision FLEXnet Connect, formerly known as InstallShield Update Service, is installed on the remote host.  It is a
software management solution for internally-developed and third-party applications, and may have been installed as part
of the FLEXnet Connect SDK, other InstallShield software, or by running FLEXnet Connect-enabled Windows software.

The version of the FLEXnet Connect client on the remote host includes an ActiveX control -- the InstallShield Update
Service Agent -- that is marked as 'safe for scripting' and contains several methods that allow for downloading and
launching arbitrary programs.  If a remote attacker can trick a user on the affected host into visiting a specially
crafted web page, this issue could be leveraged to execute arbitrary code on the host subject to the user's privileges.

Additionally, it is reportedly affected by a buffer overflow that can be triggered by passing a long argument for
'ProductCode' to the 'DownloadAndExecute()' method.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number." );
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/483062/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2007/Dec/552" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 6.0.100.65101 or later of the FLEXnet Connect client." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-5660");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Macrovision InstallShield Update Service ActiveX Unsafe Method');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119);


  script_set_attribute(attribute:"plugin_publication_date", value: "2007/11/01");
  script_set_attribute(attribute:"vuln_publication_date", value: "2007/10/30");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:macrovision:flexnet_connect");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:macrovision:installshield_2008");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:macrovision:update_service");
  script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('smb_func.inc');
include('smb_activex_func.inc');
include('debug.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

# Locate the file used by the controls.
if (activex_init() != ACX_OK) {
  dbg::log(msg:'Activex_init() != ACX_OK');
  exit(0);
}
clsid = '{E9880553-B8A7-4960-A668-95C68BED571E}';
file = activex_get_filename(clsid:clsid);
dbg::log(msg:'file: ' + obj_rep(file));

if (file)
{
  # Check its version.
  ver = activex_get_fileversion(clsid:clsid);
  dbg::log(msg:'ver: ' + obj_rep(ver));

  if (ver && activex_check_fileversion(clsid:clsid, fix:'6.0.100.65101') == TRUE)
  {
    report = NULL;
    if (report_paranoia > 1) {
      dbg::log(msg:'report_paranoia > 1');
      report =
        'Version ' + ver + ' of the vulnerable control is installed as :\n' +
        '\n' +
        '  ' + file + '\n' +
        '\n' +
        'Note, though, that Nessus did not check whether the kill bit was\n' +
        'set for the control\'s CLSID because of the Report Paranoia setting\n' +
        'in effect when this scan was run.\n';
    }
    else if (activex_get_killbit(clsid:clsid) == 0) {
      dbg::log(msg:'activex_get_killbit = 0');
      report =
        'Version ' + ver + ' of the vulnerable control is installed as :\n' +
        '\n' +
        '  ' + file + '\n' +
        '\n' +
        'Moreover, its kill bit is not set so it is accessible via Internet\n' +
        'Explorer.\n';
    }
    if (report) security_hole(port:kb_smb_transport(), extra:report);
  }

  else {
    dbg::log(msg:'ver or activex_check_fileversion is false');
  }
}
activex_end();

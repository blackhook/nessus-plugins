#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(51873);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2010-3591",
    "CVE-2010-3592",
    "CVE-2010-3595",
    "CVE-2010-3598",
    "CVE-2010-3599"
  );
  script_bugtraq_id(
    45846,
    45849,
    45851,
    45856,
    45871
  );
  script_xref(name:"EDB-ID", value:"16052");
  script_xref(name:"EDB-ID", value:"16053");
  script_xref(name:"EDB-ID", value:"16055");
  script_xref(name:"EDB-ID", value:"16056");
  script_xref(name:"SECUNIA", value:"42976");

  script_name(english:"Oracle Document Capture Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has one or more ActiveX controls installed that are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Oracle Document Capture client installed on the remote host is potentially affected by multiple vulnerabilities :

  - An unspecified vulnerability exists in the Import Export utility. An attacker can exploit this to affect
    integrity. (CVE-2010-3598)

  - An information disclosure vulnerability exists related to the EasyMail ActiveX control (emsmtp.dll).
    (CVE-2010-3595)

  - Insecure methods in the 'Actbar2.ocx' and 'empop3.dll' ActiveX controls can be exploited to overwrite
    arbitrary files. (CVE-2010-3591)

  - An error in the 'WriteJPG()' method in the NCSEcw.dll ActiveX control can be exploited to overwrite
    arbitrary files or potentially cause a buffer overflow. (CVE-2010-3599)

  - An unspecified vulnerability exists in the Internal Operations component. (CVE-2010-3592)

Note that the NCSEcw.dll control is actually from the ERDAS ECW/JP2 SDK developer toolkit from Intergraph. Note also that
Nessus has not tested for this issue but has instead relied only on the presence of the affected ActiveX components.");
  # https://web.archive.org/web/20110831133022/http://dsecrg.ru/pages/vul/show.php?id=306
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a54d748d");
  # https://web.archive.org/web/20110919025431/http://dsecrg.ru/pages/vul/show.php?id=307
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c14789b4");
  # http://www.oracle.com/technetwork/topics/security/cpujan2011-194091.html%22
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32532e3d");
  # https://geospatialcommunity.hexagon.com/s/article/Security-Advisory-for-ERDAS-ECW-JP2-SDK
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0180a060");
  script_set_attribute(attribute:"solution", value:
"If using Oracle's Document Capture client, apply the patch from Oracle to disable the ActiveX controls.

If using a different application that includes the NCSEcw.dll control, set the kill bit for the affect control as
discussed in Hexagon Geospatial's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-3599");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_activex_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");

var clsids = make_list(
  '{4932CEF4-2CAA-11D2-A165-0060081C43D9}',
  '{F647CBE5-3C01-402A-B3F0-502A77054A24}',
  '{10696DE0-CF47-4ad4-B1AE-CC1F4021D65B}',
  '{68AC0D5F-0424-11D5-822F-00C04F6BA8D9}',
  '{DAFA4BF6-C807-463c-8745-C9E0C90CF84F}',
  '{D63891F1-E026-11D3-A6C3-005004055C6C}'
);

# Determine if any of the controls are installed.
var info = '';
var installs = 0;

var clsid, file, version, s;

foreach clsid (clsids)
{
  file = activex_get_filename(clsid:clsid);
  if (isnull(file))
  {
    activex_end();
    exit(1, "activex_get_filename() returned NULL.");
  }
  if (!file) continue;

  installs++;

  # Get its version
  version = activex_get_fileversion(clsid:clsid);
  if (!version) version = 'unknown';

  if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
  {
    info += '\n  Class Identifier  : ' + clsid +
            '\n  Filename          : ' + file +
            '\n  Installed version : ' + version + '\n';

    if (!thorough_tests) break;
  }
}
activex_end();

# Report findings.
if (installs)
{
  if (info)
  {
    if (report_paranoia > 1)
    {
      if (installs == 1) s = " was";
      else s = "s were";

      report = info +
        '\n' +
        'Note, though, that Nessus did not check whether the kill bit' + s + '\n' +
        'set for the control\'s CLSID because of the Report Paranoia setting' + '\n' +
        'in effect when this scan was run.\n';
    }
    else
    {
      if (installs == 1) s = "its kill bit is not set so it is";
      else s = "their kill bits are not set so they are";

      report = info +
        '\n' +
        'Moreover, ' + s + ' accessible via Internet\n' +
        'Explorer.\n';
    }

    if (report_verbosity > 0) security_hole(port:kb_smb_transport(), extra:report);
    else security_hole(kb_smb_transport());
    exit(0);
  }
  else
  {
    if (installs == 1) exit(0, "The control is installed but its kill bit is set.");
    else exit(0, installs+" instances of the controls are installed but their kill bits are set.");
  }
}
else exit(0, "None of the affected controls are installed.");

#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84645);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/08");

  script_cve_id(
    "CVE-2014-0578",
    "CVE-2015-3097",
    "CVE-2015-3114",
    "CVE-2015-3115",
    "CVE-2015-3116",
    "CVE-2015-3117",
    "CVE-2015-3118",
    "CVE-2015-3119",
    "CVE-2015-3120",
    "CVE-2015-3121",
    "CVE-2015-3122",
    "CVE-2015-3123",
    "CVE-2015-3124",
    "CVE-2015-3125",
    "CVE-2015-3126",
    "CVE-2015-3127",
    "CVE-2015-3128",
    "CVE-2015-3129",
    "CVE-2015-3130",
    "CVE-2015-3131",
    "CVE-2015-3132",
    "CVE-2015-3133",
    "CVE-2015-3134",
    "CVE-2015-3135",
    "CVE-2015-3136",
    "CVE-2015-3137",
    "CVE-2015-4428",
    "CVE-2015-4429",
    "CVE-2015-4430",
    "CVE-2015-4431",
    "CVE-2015-4432",
    "CVE-2015-4433",
    "CVE-2015-5116",
    "CVE-2015-5117",
    "CVE-2015-5118",
    "CVE-2015-5119",
    "CVE-2015-5124"
  );
  script_bugtraq_id(
    75090,
    75568,
    75590,
    75591,
    75592,
    75593,
    75594,
    75595,
    75596
  );
  script_xref(name:"MSKB", value:"3065823");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"MS KB3065823: Update for Vulnerabilities in Adobe Flash Player in Internet Explorer");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing KB3065823. It is, therefore,
affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists that
    allows an attacker to guess the address for the Flash
    heap. (CVE-2015-3097)

  - Multiple heap-based buffer overflow vulnerabilities
    exist that allow arbitrary code execution.
    (CVE-2015-3135, CVE-2015-4432, CVE-2015-5118)

  - Multiple memory corruption vulnerabilities exist that
    allow arbitrary code execution. (CVE-2015-3117,
    CVE-2015-3123, CVE-2015-3130, CVE-2015-3133,
    CVE-2015-3134, CVE-2015-4431)

  - Multiple NULL pointer dereference flaws exist.
    (CVE-2015-3126, CVE-2015-4429)

  - A security bypass vulnerability exists that results in
    an information disclosure. (CVE-2015-3114)

  - Multiple type confusion vulnerabilities exist that allow
    arbitrary code execution. (CVE-2015-3119, CVE-2015-3120,
    CVE-2015-3121, CVE-2015-3122, CVE-2015-4433)

  - Multiple use-after-free errors exist that allow
    arbitrary code execution. (CVE-2015-3118, CVE-2015-3124,
    CVE-2015-5117, CVE-2015-3127, CVE-2015-3128,
    CVE-2015-3129, CVE-2015-3131, CVE-2015-3132,
    CVE-2015-3136, CVE-2015-3137, CVE-2015-4428,
    CVE-2015-4430, CVE-2015-5119)

  - Multiple same-origin policy bypass vulnerabilities exist
    that allow information disclosure. (CVE-2014-0578,
    CVE-2015-3115, CVE-2015-3116, CVE-2015-3125,
    CVE-2015-5116)

  - A memory corruption issue exists due to improper
    validation of user-supplied input. An attacker can
    exploit this to execute arbitrary code. (CVE-2015-5124)");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2016/2755801");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/3065823/microsoft-security-advisory-update-for-vulnerabilities-in-adobe-flash");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-16.html");
  script_set_attribute(attribute:"solution", value:
"Install Microsoft KB3065823.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5124");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player ByteArray Use After Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_activex_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

if (activex_init() != ACX_OK) audit(AUDIT_FN_FAIL, "activex_init()");

# Adobe Flash Player CLSID
clsid = '{D27CDB6E-AE6D-11cf-96B8-444553540000}';

file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  audit(AUDIT_FN_FAIL, "activex_get_filename", "NULL");
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

info = '';

iver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
 iver[i] = int(iver[i]);

# <= 18.0.0.194
if (
  (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0) &&
  (
    iver[0] < 18 ||
    (
      iver[0] == 18 &&
      (
        (iver[1] == 0 && iver[2] == 0 && iver[3] <= 194)
      )
    )
  )
)
{
  info = '\n  Path              : ' + file +
         '\n  Installed version : ' + version +
         '\n  Fixed version     : 18.0.0.203' +
         '\n';
}

port = kb_smb_transport();

if (info != '')
{
  if (report_verbosity > 0)
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
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_HOST_NOT, 'affected');

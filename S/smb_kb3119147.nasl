#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87249);
  script_version("1.13");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id(
    "CVE-2015-8045",
    "CVE-2015-8047",
    "CVE-2015-8048",
    "CVE-2015-8049",
    "CVE-2015-8050",
    "CVE-2015-8054",
    "CVE-2015-8055",
    "CVE-2015-8056",
    "CVE-2015-8057",
    "CVE-2015-8058",
    "CVE-2015-8059",
    "CVE-2015-8060",
    "CVE-2015-8061",
    "CVE-2015-8062",
    "CVE-2015-8063",
    "CVE-2015-8064",
    "CVE-2015-8065",
    "CVE-2015-8066",
    "CVE-2015-8067",
    "CVE-2015-8068",
    "CVE-2015-8069",
    "CVE-2015-8070",
    "CVE-2015-8071",
    "CVE-2015-8401",
    "CVE-2015-8402",
    "CVE-2015-8403",
    "CVE-2015-8404",
    "CVE-2015-8405",
    "CVE-2015-8406",
    "CVE-2015-8407",
    "CVE-2015-8408",
    "CVE-2015-8409",
    "CVE-2015-8410",
    "CVE-2015-8411",
    "CVE-2015-8412",
    "CVE-2015-8413",
    "CVE-2015-8414",
    "CVE-2015-8415",
    "CVE-2015-8416",
    "CVE-2015-8417",
    "CVE-2015-8418",
    "CVE-2015-8419",
    "CVE-2015-8420",
    "CVE-2015-8421",
    "CVE-2015-8422",
    "CVE-2015-8423",
    "CVE-2015-8424",
    "CVE-2015-8425",
    "CVE-2015-8426",
    "CVE-2015-8427",
    "CVE-2015-8428",
    "CVE-2015-8429",
    "CVE-2015-8430",
    "CVE-2015-8431",
    "CVE-2015-8432",
    "CVE-2015-8433",
    "CVE-2015-8434",
    "CVE-2015-8435",
    "CVE-2015-8436",
    "CVE-2015-8437",
    "CVE-2015-8438",
    "CVE-2015-8439",
    "CVE-2015-8440",
    "CVE-2015-8441",
    "CVE-2015-8442",
    "CVE-2015-8443",
    "CVE-2015-8444",
    "CVE-2015-8445",
    "CVE-2015-8446",
    "CVE-2015-8447",
    "CVE-2015-8448",
    "CVE-2015-8449",
    "CVE-2015-8450",
    "CVE-2015-8451",
    "CVE-2015-8452",
    "CVE-2015-8453",
    "CVE-2015-8454",
    "CVE-2015-8455",
    "CVE-2015-8456",
    "CVE-2015-8457"
  );
  script_bugtraq_id(
    78710,
    78712,
    78713,
    78714,
    78715,
    78716,
    78717,
    78718,
    78802
  );
  script_xref(name:"MSKB", value:"3119147");

  script_name(english:"MS KB3119147: Update for Vulnerabilities in Adobe Flash Player in Internet Explorer and Microsoft Edge");
  script_summary(english:"Checks the version of the ActiveX control.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing KB3119147. It is, therefore,
affected by multiple vulnerabilities :
  
  - Multiple heap buffer overflow conditions exist that
    allow an attacker to execute arbitrary code.
    (CVE-2015-8438, CVE-2015-8446)

  - Multiple memory corruption issues exist that allow an
    attacker to execute arbitrary code. (CVE-2015-8045,
    CVE-2015-8047, CVE-2015-8060, CVE-2015-8408,
    CVE-2015-8416, CVE-2015-8417, CVE-2015-8418,
    CVE-2015-8419, CVE-2015-8443, CVE-2015-8444,
    CVE-2015-8451, CVE-2015-8455)

  - Multiple security bypass vulnerabilities exist that
    allow an attacker to write arbitrary data to the file
    system under user permissions. (CVE-2015-8453,
    CVE-2015-8440,  CVE-2015-8409)

  - A stack buffer overflow condition exists that allows an
    attacker to execute arbitrary code. (CVE-2015-8407,
    CVE-2015-8457)

  - A type confusion error exists that allows an attacker to
    execute arbitrary code. (CVE-2015-8439, CVE-2015-8456)

  - An integer overflow condition exists that allows an
    attacker to execute arbitrary code. (CVE-2015-8445)

  - A buffer overflow condition exists that allows an
    attacker to execute arbitrary code. (CVE-2015-8415)

  - Multiple use-after-free errors exist that allow an
    attacker to execute arbitrary code. (CVE-2015-8048,
    CVE-2015-8049, CVE-2015-8050, CVE-2015-8055,
    CVE-2015-8056, CVE-2015-8057, CVE-2015-8058,
    CVE-2015-8059, CVE-2015-8061, CVE-2015-8062,
    CVE-2015-8063, CVE-2015-8064, CVE-2015-8065,
    CVE-2015-8066, CVE-2015-8067, CVE-2015-8068,
    CVE-2015-8069, CVE-2015-8070, CVE-2015-8071,
    CVE-2015-8401, CVE-2015-8402, CVE-2015-8403,
    CVE-2015-8404, CVE-2015-8405, CVE-2015-8406,
    CVE-2015-8410, CVE-2015-8411, CVE-2015-8412,
    CVE-2015-8413, CVE-2015-8414, CVE-2015-8420,
    CVE-2015-8421, CVE-2015-8422, CVE-2015-8423,
    CVE-2015-8424, CVE-2015-8425, CVE-2015-8426,
    CVE-2015-8427, CVE-2015-8428, CVE-2015-8429,
    CVE-2015-8430, CVE-2015-8431, CVE-2015-8432,
    CVE-2015-8433, CVE-2015-8434, CVE-2015-8435,
    CVE-2015-8436, CVE-2015-8437, CVE-2015-8441,
    CVE-2015-8442, CVE-2015-8447, CVE-2015-8448,
    CVE-2015-8449, CVE-2015-8450, CVE-2015-8452,
    CVE-2015-8454)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-27.html");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/3119147/microsoft-security-advisory-update-for-vulnerabilities-in-adobe-flash");
  script_set_attribute(attribute:"solution", value:
"Install Microsoft KB3119147.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8457");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (hotfix_check_sp_range(win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
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
iver = join(iver, sep:".");

# all < 18.0.0.268 or 19 < 20.0.0.228
fix = FALSE;
if(iver =~ "^(19|20)\." && ver_compare(ver:iver, fix:"20.0.0.228", strict:FALSE) < 0)
  fix = "20.0.0.228";
else if(ver_compare(ver:iver, fix:"18.0.0.268", strict:FALSE) < 0)
  fix = "18.0.0.268";

if (
  (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0) &&
  fix
)
{
  info = '\n  Path              : ' + file +
         '\n  Installed version : ' + version +
         '\n  Fixed version     : ' + fix +
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

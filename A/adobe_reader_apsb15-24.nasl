#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86403);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/18");

  script_cve_id(
    "CVE-2015-5583",
    "CVE-2015-5586",
    "CVE-2015-6683",
    "CVE-2015-6684",
    "CVE-2015-6685",
    "CVE-2015-6686",
    "CVE-2015-6687",
    "CVE-2015-6688",
    "CVE-2015-6689",
    "CVE-2015-6690",
    "CVE-2015-6691",
    "CVE-2015-6692",
    "CVE-2015-6693",
    "CVE-2015-6694",
    "CVE-2015-6695",
    "CVE-2015-6696",
    "CVE-2015-6697",
    "CVE-2015-6698",
    "CVE-2015-6699",
    "CVE-2015-6700",
    "CVE-2015-6701",
    "CVE-2015-6702",
    "CVE-2015-6703",
    "CVE-2015-6704",
    "CVE-2015-6705",
    "CVE-2015-6706",
    "CVE-2015-6707",
    "CVE-2015-6708",
    "CVE-2015-6709",
    "CVE-2015-6710",
    "CVE-2015-6711",
    "CVE-2015-6712",
    "CVE-2015-6713",
    "CVE-2015-6714",
    "CVE-2015-6715",
    "CVE-2015-6716",
    "CVE-2015-6717",
    "CVE-2015-6718",
    "CVE-2015-6719",
    "CVE-2015-6720",
    "CVE-2015-6721",
    "CVE-2015-6722",
    "CVE-2015-6723",
    "CVE-2015-6724",
    "CVE-2015-6725",
    "CVE-2015-7614",
    "CVE-2015-7615",
    "CVE-2015-7616",
    "CVE-2015-7617",
    "CVE-2015-7618",
    "CVE-2015-7619",
    "CVE-2015-7620",
    "CVE-2015-7621",
    "CVE-2015-7622",
    "CVE-2015-7623",
    "CVE-2015-7624",
    "CVE-2015-7650",
    "CVE-2015-7829",
    "CVE-2015-8458"
  );
  script_bugtraq_id(
    77064,
    77066,
    77067,
    77068,
    77069,
    77070,
    77074,
    79208
  );

  script_name(english:"Adobe Reader <= 10.1.15 / 11.0.12 / 2015.006.30060 / 2015.008.20082 Multiple Vulnerabilities (APSB15-24)");
  script_summary(english:"Checks the version of Adobe Reader.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Windows host is
version 10.1.15 / 11.0.12 / 2015.006.30060 / 2015.008.20082 or
earlier. It is, therefore, affected by multiple vulnerabilities :

  - A buffer overflow condition exists that allows an
    attacker to disclose information. (CVE-2015-6692)

  - Multiple use-after-free errors exist that allow an
    attacker to execute arbitrary code. (CVE-2015-6689,
    CVE-2015-6688, CVE-2015-6690, CVE-2015-7615,
    CVE-2015-7617, CVE-2015-6687, CVE-2015-6684,
    CVE-2015-6691, CVE-2015-7621, CVE-2015-5586,
    CVE-2015-6683)

  - Multiple heap buffer overflow conditions exist that
    allow an attacker to execute arbitrary code.
    (CVE-2015-6696, CVE-2015-6698, CVE-2015-8458)

  - Multiple memory corruption issues exist that allow a
    remote attacker to execute arbitrary code.
    (CVE-2015-6685, CVE-2015-6693, CVE-2015-6694,
    CVE-2015-6695, CVE-2015-6686, CVE-2015-7622,
    CVE-2015-7650)

  - Multiple unspecified memory leak vulnerabilities exist.
    (CVE-2015-6699, CVE-2015-6700, CVE-2015-6701,
    CVE-2015-6702, CVE-2015-6703, CVE-2015-6704,
    CVE-2015-6697)

  - Multiple security bypass vulnerabilities exist that
    allow a remote attacker to disclose information.
    (CVE-2015-5583, CVE-2015-6705, CVE-2015-6706,
    CVE-2015-7624)

  - Multiple security bypass vulnerabilities exists that
    allow an attacker to bypass JavaScript API execution.
    (CVE-2015-6707, CVE-2015-6708, CVE-2015-6709,
    CVE-2015-6710, CVE-2015-6711, CVE-2015-6712,
    CVE-2015-7614, CVE-2015-7616, CVE-2015-6716,
    CVE-2015-6717, CVE-2015-6718, CVE-2015-6719,
    CVE-2015-6720, CVE-2015-6721, CVE-2015-6722,
    CVE-2015-6723, CVE-2015-6724, CVE-2015-6725,
    CVE-2015-7618, CVE-2015-7619, CVE-2015-7620,
    CVE-2015-7623, CVE-2015-6713, CVE-2015-6714,
    CVE-2015-6715)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb15-24.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader 10.1.16 / 11.0.13 / 2015.006.30094 / 
2015.009.20069 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7622");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Reader");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_name = "Adobe Reader";
install = get_single_install(app_name:app_name);

version = install['version'];
path    = install['path'];
verui   = install['display_version'];

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Affected is :
#
# 10.x <= 10.1.15
# 11.x <= 11.0.12
# DC Classic <= 2015.006.30060
# DC Continuous <= 2015.008.20082
if (
  (ver[0] == 10 && ver[1] < 1) ||
  (ver[0] == 10 && ver[1] == 1 && ver[2] <= 15) ||
  (ver[0] == 11 && ver[1] == 0 && ver[2] <= 12) ||
  (ver[0] == 15 && ver[1] == 6 && ver[2] <= 30060) ||
  (ver[0] == 15 && ver[1] == 7 ) ||
  (ver[0] == 15 && ver[1] == 8 && ver[2] <= 20082)
)
{
  port = get_kb_item('SMB/transport');
  if(!port) port = 445;
  report = '\n  Path              : '+path+
           '\n  Installed version : '+verui+
           '\n  Fixed version     : 10.1.16 / 11.0.13 / 2015.006.30094 / 2015.009.20069' +
           '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, verui, path);

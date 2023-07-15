#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104386);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/25");

  script_cve_id(
    "CVE-2017-13986",
    "CVE-2017-13987",
    "CVE-2017-13988",
    "CVE-2017-13989",
    "CVE-2017-13990",
    "CVE-2017-13991",
    "CVE-2017-14356",
    "CVE-2017-14357",
    "CVE-2017-14358"
  );
  script_bugtraq_id(100935, 101627);
  script_xref(name:"IAVA", value:"2017-A-0317");

  script_name(english:"HP ArcSight ESM 6.x < 6.9.1.2377.4 / 6.11.0.2385.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the ArcSight ESM version number.");

  script_set_attribute(attribute:"synopsis", value:
"A security management system installed on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of HP
ArcSight Enterprise Security Manager (ESM) installed on the remote
host is 6.x prior to 6.9.1c Patch 4 or 6.11.0 Patch 1. It is, therefore, affected by multiple 
vulnerabilities. See advisory for details.");
  # https://cf.passport.softwaregrp.com/hppcf/login.do?hpappid=206728_SSO_PRO&TYPE=33554433&REALMOID=06-000e9b59-5755-18f0-a414-00bd0f78a02e&GUID=&SMAUTHREASON=0&METHOD=GET&SMAGENTNAME=$SM$o8O1D10%2ftKElla5TtPp65rDrT5k5G0zxLqneTAG5uysO3%2f7yctjoO3h5%2fRpka45ewHx55dv9NlXXfizkUS%2fjPEDb6N%2fozvWQ&TARGET=$SM$https%3a%2f%2fsoftwaresupport.softwaregrp.com%2fkm%2fKM02996760
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?41d3543f");
  # https://softwaresupport.softwaregrp.com/document/-/facetsearch/document/KM02944672
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4efce1c");
  # https://cf.passport.softwaregrp.com/hppcf/login.do?hpappid=206728_SSO_PRO&TYPE=33554433&REALMOID=06-000a5aa8-5753-18f0-a414-00bd0f78a02e&GUID=&SMAUTHREASON=0&METHOD=GET&SMAGENTNAME=$SM$o8O1D10%2ftKElla5TtPp65rDrT5k5G0zxLqneTAG5uysO3%2f7yctjoO3h5%2fRpka45ewHx55dv9NlXXfizkUS%2fjPEDb6N%2fozvWQ&TARGET=$SM$https%3a%2f%2fsoftwaresupport.softwaregrp.com%2fgroup%2fsoftwaresupport%2fsearch-result%2f-%2ffacetsearch%2fdocument%2fKM02857868
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea3f9f0e");
  # https://cf.passport.softwaregrp.com/hppcf/login.do?hpappid=206728_SSO_PRO&TYPE=33554433&REALMOID=06-000a5aa8-5753-18f0-a414-00bd0f78a02e&GUID=&SMAUTHREASON=0&METHOD=GET&SMAGENTNAME=$SM$o8O1D10%2ftKElla5TtPp65rDrT5k5G0zxLqneTAG5uysO3%2f7yctjoO3h5%2fRpka45ewHx55dv9NlXXfizkUS%2fjPEDb6N%2fozvWQ&TARGET=$SM$https%3a%2f%2fsoftwaresupport.softwaregrp.com%2fgroup%2fsoftwaresupport%2fsearch-result%2f-%2ffacetsearch%2fdocument%2fKM02906815
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f40fba9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP ArcSight ESM version 6.9.1.2377.4 (6.9.1c Patch 4) / 6.11.0.2385.1 (6.11.0 Patch 1) or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14356");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:arcsight_enterprise_security_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_arcsight_esm_installed.nbin");
  script_require_keys("installed_sw/HP ArcSight Enterprise Security Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "HP ArcSight Enterprise Security Manager";
port = 0;

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
ver = install['version'];
path = install['path'];
fix = NULL;

if (ver =~ "6\.[0-9]\." && ver_compare(ver:ver, fix:"6.9.1.2377.4", strict:FALSE) < 0)
{
  fix = '6.9.1.2377.4';
  display_fix = '6.9.1c Patch 4';
}
else if(ver =~ "6\.11\." && ver_compare(ver:ver, fix:"6.11.0.2385.1", strict:FALSE) < 0)
{
  fix = '6.11.0.2385.1';
  display_fix = '6.11.0 Patch 1';
}

if(fix)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + display_fix + '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE, xss:TRUE, sqli:TRUE);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app, ver);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91099);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id(
    "CVE-2016-1037",
    "CVE-2016-1038",
    "CVE-2016-1039",
    "CVE-2016-1040",
    "CVE-2016-1041",
    "CVE-2016-1042",
    "CVE-2016-1043",
    "CVE-2016-1044",
    "CVE-2016-1045",
    "CVE-2016-1046",
    "CVE-2016-1047",
    "CVE-2016-1048",
    "CVE-2016-1049",
    "CVE-2016-1050",
    "CVE-2016-1051",
    "CVE-2016-1052",
    "CVE-2016-1053",
    "CVE-2016-1054",
    "CVE-2016-1055",
    "CVE-2016-1056",
    "CVE-2016-1057",
    "CVE-2016-1058",
    "CVE-2016-1059",
    "CVE-2016-1060",
    "CVE-2016-1061",
    "CVE-2016-1062",
    "CVE-2016-1063",
    "CVE-2016-1064",
    "CVE-2016-1065",
    "CVE-2016-1066",
    "CVE-2016-1067",
    "CVE-2016-1068",
    "CVE-2016-1069",
    "CVE-2016-1070",
    "CVE-2016-1071",
    "CVE-2016-1072",
    "CVE-2016-1073",
    "CVE-2016-1074",
    "CVE-2016-1075",
    "CVE-2016-1076",
    "CVE-2016-1077",
    "CVE-2016-1078",
    "CVE-2016-1079",
    "CVE-2016-1080",
    "CVE-2016-1081",
    "CVE-2016-1082",
    "CVE-2016-1083",
    "CVE-2016-1084",
    "CVE-2016-1085",
    "CVE-2016-1086",
    "CVE-2016-1087",
    "CVE-2016-1088",
    "CVE-2016-1090",
    "CVE-2016-1092",
    "CVE-2016-1093",
    "CVE-2016-1094",
    "CVE-2016-1095",
    "CVE-2016-1112",
    "CVE-2016-1116",
    "CVE-2016-1117",
    "CVE-2016-1118",
    "CVE-2016-1119",
    "CVE-2016-1120",
    "CVE-2016-1121",
    "CVE-2016-1122",
    "CVE-2016-1123",
    "CVE-2016-1124",
    "CVE-2016-1125",
    "CVE-2016-1126",
    "CVE-2016-1127",
    "CVE-2016-1128",
    "CVE-2016-1129",
    "CVE-2016-1130",
    "CVE-2016-4088",
    "CVE-2016-4089",
    "CVE-2016-4090",
    "CVE-2016-4091",
    "CVE-2016-4092",
    "CVE-2016-4093",
    "CVE-2016-4094",
    "CVE-2016-4096",
    "CVE-2016-4097",
    "CVE-2016-4098",
    "CVE-2016-4099",
    "CVE-2016-4100",
    "CVE-2016-4101",
    "CVE-2016-4102",
    "CVE-2016-4103",
    "CVE-2016-4104",
    "CVE-2016-4105",
    "CVE-2016-4106",
    "CVE-2016-4107",
    "CVE-2016-4119"
  );
  script_bugtraq_id(90517);
  script_xref(name:"ZDI", value:"ZDI-16-285");
  script_xref(name:"ZDI", value:"ZDI-16-286");
  script_xref(name:"ZDI", value:"ZDI-16-287");
  script_xref(name:"ZDI", value:"ZDI-16-288");
  script_xref(name:"ZDI", value:"ZDI-16-289");
  script_xref(name:"ZDI", value:"ZDI-16-290");
  script_xref(name:"ZDI", value:"ZDI-16-291");
  script_xref(name:"ZDI", value:"ZDI-16-292");
  script_xref(name:"ZDI", value:"ZDI-16-293");
  script_xref(name:"ZDI", value:"ZDI-16-294");
  script_xref(name:"ZDI", value:"ZDI-16-295");
  script_xref(name:"ZDI", value:"ZDI-16-296");
  script_xref(name:"ZDI", value:"ZDI-16-297");
  script_xref(name:"ZDI", value:"ZDI-16-298");
  script_xref(name:"ZDI", value:"ZDI-16-299");
  script_xref(name:"ZDI", value:"ZDI-16-300");
  script_xref(name:"ZDI", value:"ZDI-16-301");
  script_xref(name:"ZDI", value:"ZDI-16-302");
  script_xref(name:"ZDI", value:"ZDI-16-303");
  script_xref(name:"ZDI", value:"ZDI-16-304");
  script_xref(name:"ZDI", value:"ZDI-16-305");
  script_xref(name:"ZDI", value:"ZDI-16-306");
  script_xref(name:"ZDI", value:"ZDI-16-307");
  script_xref(name:"ZDI", value:"ZDI-16-308");
  script_xref(name:"ZDI", value:"ZDI-16-309");
  script_xref(name:"ZDI", value:"ZDI-16-310");
  script_xref(name:"ZDI", value:"ZDI-16-311");
  script_xref(name:"ZDI", value:"ZDI-16-312");
  script_xref(name:"ZDI", value:"ZDI-16-313");
  script_xref(name:"ZDI", value:"ZDI-16-315");
  script_xref(name:"ZDI", value:"ZDI-16-316");
  script_xref(name:"ZDI", value:"ZDI-16-317");
  script_xref(name:"ZDI", value:"ZDI-16-318");
  script_xref(name:"ZDI", value:"ZDI-16-319");
  script_xref(name:"ZDI", value:"ZDI-16-320");
  script_xref(name:"ZDI", value:"ZDI-16-321");
  script_xref(name:"ZDI", value:"ZDI-16-322");
  script_xref(name:"ZDI", value:"ZDI-16-323");
  script_xref(name:"ZDI", value:"ZDI-16-324");
  script_xref(name:"ZDI", value:"ZDI-16-325");
  script_xref(name:"ZDI", value:"ZDI-16-326");
  script_xref(name:"ZDI", value:"ZDI-16-327");
  script_xref(name:"ZDI", value:"ZDI-16-328");
  script_xref(name:"ZDI", value:"ZDI-16-329");

  script_name(english:"Adobe Reader < 11.0.16 / 15.006.30172 / 15.016.20039 Multiple Vulnerabilities (APSB16-14) (Mac OS X)");
  script_summary(english:"Checks the version of Adobe Reader.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader installed on the remote Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote Mac OS X host is
prior to 11.0.16, 15.006.30172, or 15.016.20039. It is, therefore,
affected by multiple vulnerabilities :

  - Multiple use-after-free errors exist that allow an
    attacker to execute arbitrary code. (CVE-2016-1045,
    CVE-2016-1046, CVE-2016-1047, CVE-2016-1048,
    CVE-2016-1049, CVE-2016-1050, CVE-2016-1051,
    CVE-2016-1052, CVE-2016-1053, CVE-2016-1054,
    CVE-2016-1055, CVE-2016-1056, CVE-2016-1057,
    CVE-2016-1058, CVE-2016-1059, CVE-2016-1060,
    CVE-2016-1061, CVE-2016-1065, CVE-2016-1066,
    CVE-2016-1067, CVE-2016-1068, CVE-2016-1069,
    CVE-2016-1070, CVE-2016-1075, CVE-2016-1094,
    CVE-2016-1121, CVE-2016-1122, CVE-2016-4102,
    CVE-2016-4107)

  - Multiple heap buffer overflow conditions exist that
    allow an attacker to execute arbitrary code.
    (CVE-2016-4091, CVE-2016-4092)

  - Multiple memory corruption issues exist that allow an
    attacker to execute arbitrary code. (CVE-2016-1037,
    CVE-2016-1063, CVE-2016-1064, CVE-2016-1071,
    CVE-2016-1072, CVE-2016-1073, CVE-2016-1074,
    CVE-2016-1076, CVE-2016-1077, CVE-2016-1078,
    CVE-2016-1080, CVE-2016-1081, CVE-2016-1082,
    CVE-2016-1083, CVE-2016-1084, CVE-2016-1085,
    CVE-2016-1086, CVE-2016-1088, CVE-2016-1093,
    CVE-2016-1095, CVE-2016-1116, CVE-2016-1118,
    CVE-2016-1119, CVE-2016-1120, CVE-2016-1123,
    CVE-2016-1124, CVE-2016-1125, CVE-2016-1126,
    CVE-2016-1127, CVE-2016-1128, CVE-2016-1129,
    CVE-2016-1130, CVE-2016-4088, CVE-2016-4089,
    CVE-2016-4090, CVE-2016-4093, CVE-2016-4094,
    CVE-2016-4096, CVE-2016-4097, CVE-2016-4098,
    CVE-2016-4099, CVE-2016-4100, CVE-2016-4101,
    CVE-2016-4103, CVE-2016-4104, CVE-2016-4105,
    CVE-2016-4119)

  - An integer overflow vulnerability exists that allows an
    attacker to execute arbitrary code. (CVE-2016-1043)

  - Multiple memory leak issues exist that allow an attacker
    to have an unspecified impact. (CVE-2016-1079,
    CVE-2016-1092)

  - An unspecified flaw exists that allows an attacker to
    disclose sensitive information. (CVE-2016-1112)

  - Multiple vulnerabilities exist that allow an attacker to
    bypass restrictions on JavaScript API execution.
    (CVE-2016-1038, CVE-2016-1039, CVE-2016-1040,
    CVE-2016-1041, CVE-2016-1042, CVE-2016-1044,
    CVE-2016-1062, CVE-2016-1117)

  - Multiple flaws exist when loading dynamic-link
    libraries. An attacker can exploit this, via a specially
    crafted .dll file, to execute arbitrary code.
    (CVE-2016-1087, CVE-2016-1090, CVE-2016-4106)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/acrobat/apsb16-14.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader version 11.0.16 / 15.006.30172 / 15.016.20039
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4119");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_reader_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Reader");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");
os = get_kb_item("Host/MacOSX/Version");
if (empty_or_null(os)) audit(AUDIT_OS_NOT, "Mac OS X");

app_name = "Adobe Reader";
install = get_single_install(app_name:app_name);

version = install['version'];
path    = install['path'];

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Affected is :
#
# 11.x < 11.0.16
# DC Classic < 15.006.30172
# DC Continuous < 15.016.20039
if (
  (ver[0] == 11 && ver[1] == 0 && ver[2] <= 15) ||
  (ver[0] == 15 && ver[1] == 6 && ver[2] <= 30171) ||
  (ver[0] == 15 && ver[1] >= 7 && ver[1] <= 15) ||
  (ver[0] == 15 && ver[1] == 16 && ver[2] <= 20038)
)
{
  report = '\n  Path              : '+path+
           '\n  Installed version : '+version+
           '\n  Fixed version     : 11.0.16 / 15.006.30172 / 15.016.20039' +
           '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

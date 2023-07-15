#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168273);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/06");

  script_cve_id(
    "CVE-2022-4174",
    "CVE-2022-4175",
    "CVE-2022-4176",
    "CVE-2022-4177",
    "CVE-2022-4178",
    "CVE-2022-4179",
    "CVE-2022-4180",
    "CVE-2022-4181",
    "CVE-2022-4182",
    "CVE-2022-4183",
    "CVE-2022-4184",
    "CVE-2022-4185",
    "CVE-2022-4186",
    "CVE-2022-4187",
    "CVE-2022-4188",
    "CVE-2022-4189",
    "CVE-2022-4190",
    "CVE-2022-4191",
    "CVE-2022-4192",
    "CVE-2022-4193",
    "CVE-2022-4194",
    "CVE-2022-4195"
  );
  script_xref(name:"IAVA", value:"2022-A-0501-S");

  script_name(english:"Google Chrome < 108.0.5359.71 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 108.0.5359.71. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2022_11_stable-channel-update-for-desktop_29 advisory.

  - Type Confusion in V8. (CVE-2022-4174)

  - Use after free in Camera Capture. (CVE-2022-4175)

  - Out of bounds write in Lacros Graphics. (CVE-2022-4176)

  - Use after free in Extensions. (CVE-2022-4177)

  - Use after free in Mojo. (CVE-2022-4178, CVE-2022-4180)

  - Use after free in Audio. (CVE-2022-4179)

  - Use after free in Forms. (CVE-2022-4181)

  - Inappropriate implementation in Fenced Frames. (CVE-2022-4182)

  - Insufficient policy enforcement in Popup Blocker. (CVE-2022-4183)

  - Insufficient policy enforcement in Autofill. (CVE-2022-4184)

  - Inappropriate implementation in Navigation. (CVE-2022-4185)

  - Insufficient validation of untrusted input in Downloads. (CVE-2022-4186)

  - Insufficient policy enforcement in DevTools. (CVE-2022-4187, CVE-2022-4189)

  - Insufficient validation of untrusted input in CORS. (CVE-2022-4188)

  - Insufficient data validation in Directory. (CVE-2022-4190)

  - Use after free in Sign-In. (CVE-2022-4191)

  - Use after free in Live Caption. (CVE-2022-4192)

  - Insufficient policy enforcement in File System API. (CVE-2022-4193)

  - Use after free in Accessibility. (CVE-2022-4194)

  - Insufficient policy enforcement in Safe Browsing. (CVE-2022-4195)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/11/stable-channel-update-for-desktop_29.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf710783");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1379054");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1381401");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1361066");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1379242");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1376099");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1377783");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1378564");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1382581");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1368739");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1251790");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1358647");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1373025");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1377165");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1381217");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1340879");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1344647");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1378997");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1373941");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1344514");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1354518");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1370562");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1371926");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 108.0.5359.71 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4194");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('SMB/Google_Chrome/Installed');
var installs = get_kb_list('SMB/Google_Chrome/*');

google_chrome_check_version(installs:installs, fix:'108.0.5359.71', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);

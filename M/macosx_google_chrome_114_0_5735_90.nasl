#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176495);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id(
    "CVE-2023-2929",
    "CVE-2023-2930",
    "CVE-2023-2931",
    "CVE-2023-2932",
    "CVE-2023-2933",
    "CVE-2023-2934",
    "CVE-2023-2935",
    "CVE-2023-2936",
    "CVE-2023-2937",
    "CVE-2023-2938",
    "CVE-2023-2939",
    "CVE-2023-2940",
    "CVE-2023-2941"
  );
  script_xref(name:"IAVA", value:"2023-A-0270-S");

  script_name(english:"Google Chrome < 114.0.5735.90 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 114.0.5735.90. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2023_05_stable-channel-update-for-desktop_30 advisory.

  - Out of bounds write in Swiftshader. (CVE-2023-2929)

  - Use after free in Extensions. (CVE-2023-2930)

  - Use after free in PDF. (CVE-2023-2931, CVE-2023-2932, CVE-2023-2933)

  - Out of bounds memory access in Mojo. (CVE-2023-2934)

  - Type Confusion in V8. (CVE-2023-2935, CVE-2023-2936)

  - Inappropriate implementation in Picture In Picture. (CVE-2023-2937, CVE-2023-2938)

  - Insufficient data validation in Installer. (CVE-2023-2939)

  - Inappropriate implementation in Downloads. (CVE-2023-2940)

  - Inappropriate implementation in Extensions API. (CVE-2023-2941)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1410191");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1443401");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1444238");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1444581");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1445426");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1429720");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1440695");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1443452");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1413813");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1416350");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1427431");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1426807");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1430269");
  # https://chromereleases.googleblog.com/2023/05/stable-channel-update-for-desktop_30.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b14a3c61");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 114.0.5735.90 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2936");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'114.0.5735.90', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);

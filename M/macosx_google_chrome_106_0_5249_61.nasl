#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165503);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2022-3201",
    "CVE-2022-3304",
    "CVE-2022-3305",
    "CVE-2022-3306",
    "CVE-2022-3307",
    "CVE-2022-3308",
    "CVE-2022-3309",
    "CVE-2022-3310",
    "CVE-2022-3311",
    "CVE-2022-3312",
    "CVE-2022-3313",
    "CVE-2022-3314",
    "CVE-2022-3315",
    "CVE-2022-3316",
    "CVE-2022-3317",
    "CVE-2022-3318",
    "CVE-2022-3444"
  );
  script_xref(name:"IAVA", value:"2022-A-0379-S");
  script_xref(name:"IAVA", value:"2022-A-0388-S");
  script_xref(name:"IAVA", value:"2022-A-0394-S");

  script_name(english:"Google Chrome < 106.0.5249.61 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 106.0.5249.61. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2022_09_stable-channel-update-for-desktop_27 advisory.

  - Use after free in ChromeOS Notifications in Google Chrome on ChromeOS prior to 106.0.5249.62 allowed a
    remote attacker who convinced a user to reboot Chrome OS to potentially exploit heap corruption via UI
    interaction. (Chromium security severity: Low) (CVE-2022-3318)

  - Insufficient validation of untrusted input in DevTools in Google Chrome on Chrome OS prior to
    105.0.5195.125 allowed an attacker who convinced a user to install a malicious extension to bypass
    navigation restrictions via a crafted HTML page. (Chromium security severity: High) (CVE-2022-3201)

  - Use after free in CSS in Google Chrome prior to 106.0.5249.62 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2022-3304)

  - Use after free in survey in Google Chrome on ChromeOS prior to 106.0.5249.62 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2022-3305, CVE-2022-3306)

  - Use after free in media in Google Chrome prior to 106.0.5249.62 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2022-3307)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/09/stable-channel-update-for-desktop_27.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97263b93");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1358907");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1343104");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1319229");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1320139");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1323488");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1342722");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1348415");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1240065");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1302813");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1303306");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1317904");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1328708");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1322812");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1333623");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1300539");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1318791");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 106.0.5249.61 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3318");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3315");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'106.0.5249.61', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);

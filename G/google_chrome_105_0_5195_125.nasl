#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165068);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2022-3195",
    "CVE-2022-3196",
    "CVE-2022-3197",
    "CVE-2022-3198",
    "CVE-2022-3199",
    "CVE-2022-3200",
    "CVE-2022-3201"
  );
  script_xref(name:"IAVA", value:"2022-A-0379-S");
  script_xref(name:"IAVA", value:"2022-A-0388-S");
  script_xref(name:"IAVA", value:"2022-A-0394-S");

  script_name(english:"Google Chrome < 105.0.5195.125 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 105.0.5195.125. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2022_09_stable-channel-update-for-desktop_14 advisory.

  - Use after free in Frames in Google Chrome prior to 105.0.5195.125 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2022-3199)

  - Out of bounds write in Storage in Google Chrome prior to 105.0.5195.125 allowed a remote attacker to
    perform an out of bounds memory write via a crafted HTML page. (Chromium security severity: High)
    (CVE-2022-3195)

  - Use after free in PDF in Google Chrome prior to 105.0.5195.125 allowed a remote attacker to potentially
    exploit heap corruption via a crafted PDF file. (Chromium security severity: High) (CVE-2022-3196,
    CVE-2022-3197, CVE-2022-3198)

  - Heap buffer overflow in Internals in Google Chrome prior to 105.0.5195.125 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2022-3200)

  - Insufficient validation of untrusted input in DevTools in Google Chrome on Chrome OS prior to
    105.0.5195.125 allowed an attacker who convinced a user to install a malicious extension to bypass
    navigation restrictions via a crafted HTML page. (Chromium security severity: High) (CVE-2022-3201)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/09/stable-channel-update-for-desktop_14.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fe4c0310");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1358381");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1358090");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1358075");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1355682");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1355237");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1355103");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1343104");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 105.0.5195.125 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3199");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3200");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
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

google_chrome_check_version(installs:installs, fix:'105.0.5195.125', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);

#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174478);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/04");

  script_cve_id(
    "CVE-2023-2133",
    "CVE-2023-2134",
    "CVE-2023-2135",
    "CVE-2023-2136",
    "CVE-2023-2137"
  );
  script_xref(name:"IAVA", value:"2023-A-0203-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/05/12");

  script_name(english:"Google Chrome < 112.0.5615.137 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 112.0.5615.137. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2023_04_stable-channel-update-for-desktop_18 advisory.

  - Out of bounds memory access in Service Worker API in Google Chrome prior to 112.0.5615.137 allowed a
    remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security
    severity: High) (CVE-2023-2133, CVE-2023-2134)

  - Use after free in DevTools in Google Chrome prior to 112.0.5615.137 allowed a remote attacker who
    convinced a user to enable specific preconditions to potentially exploit heap corruption via a crafted
    HTML page. (Chromium security severity: High) (CVE-2023-2135)

  - Integer overflow in Skia in Google Chrome prior to 112.0.5615.137 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (Chromium security severity: High) (CVE-2023-2136)

  - Heap buffer overflow in sqlite in Google Chrome prior to 112.0.5615.137 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-2137)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2023/04/stable-channel-update-for-desktop_18.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cfef4477");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1429197");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1429201");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1424337");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1432603");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1430644");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 112.0.5615.137 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2135");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-2136");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('SMB/Google_Chrome/Installed');
var installs = get_kb_list('SMB/Google_Chrome/*');

google_chrome_check_version(installs:installs, fix:'112.0.5615.137', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);

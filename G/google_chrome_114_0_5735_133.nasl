#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177227);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id(
    "CVE-2023-3214",
    "CVE-2023-3215",
    "CVE-2023-3216",
    "CVE-2023-3217"
  );
  script_xref(name:"IAVA", value:"2023-A-0301-S");

  script_name(english:"Google Chrome < 114.0.5735.133 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 114.0.5735.133. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2023_06_stable-channel-update-for-desktop_13 advisory.

  - Use after free in Autofill payments. (CVE-2023-3214)

  - Use after free in WebRTC. (CVE-2023-3215)

  - Type Confusion in V8. (CVE-2023-3216)

  - Use after free in WebXR. (CVE-2023-3217)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1450568");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1446274");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1450114");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1450601");
  # https://chromereleases.googleblog.com/2023/06/stable-channel-update-for-desktop_13.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a05ebc7f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 114.0.5735.133 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3217");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/13");

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

google_chrome_check_version(installs:installs, fix:'114.0.5735.133', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);

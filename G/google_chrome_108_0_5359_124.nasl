#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168699);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id(
    "CVE-2022-4436",
    "CVE-2022-4437",
    "CVE-2022-4438",
    "CVE-2022-4439",
    "CVE-2022-4440"
  );
  script_xref(name:"IAVA", value:"2022-A-0528-S");

  script_name(english:"Google Chrome < 108.0.5359.124 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 108.0.5359.124. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2022_12_stable-channel-update-for-desktop_13 advisory.

  - Use after free in Blink Media. (CVE-2022-4436)

  - Use after free in Mojo IPC. (CVE-2022-4437)

  - Use after free in Blink Frames. (CVE-2022-4438)

  - Use after free in Aura. (CVE-2022-4439)

  - Use after free in Profiles. (CVE-2022-4440)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/12/stable-channel-update-for-desktop_13.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d39358a7");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1383991");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1394692");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1381871");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1392661");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1382761");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 108.0.5359.124 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4440");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/13");

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

google_chrome_check_version(installs:installs, fix:'108.0.5359.124', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);

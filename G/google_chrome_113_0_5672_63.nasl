#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175001);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/19");

  script_cve_id(
    "CVE-2023-2459",
    "CVE-2023-2460",
    "CVE-2023-2461",
    "CVE-2023-2462",
    "CVE-2023-2463",
    "CVE-2023-2464",
    "CVE-2023-2465",
    "CVE-2023-2466",
    "CVE-2023-2467",
    "CVE-2023-2468"
  );
  script_xref(name:"IAVA", value:"2023-A-0236-S");

  script_name(english:"Google Chrome < 113.0.5672.63 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 113.0.5672.63. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2023_05_stable-channel-update-for-desktop advisory.

  - Inappropriate implementation in Prompts. (CVE-2023-2459, CVE-2023-2462, CVE-2023-2466, CVE-2023-2467)

  - Insufficient validation of untrusted input in Extensions. (CVE-2023-2460)

  - Use after free in OS Inputs. (CVE-2023-2461)

  - Inappropriate implementation in Full Screen Mode. (CVE-2023-2463)

  - Inappropriate implementation in PictureInPicture. (CVE-2023-2464, CVE-2023-2468)

  - Inappropriate implementation in CORS. (CVE-2023-2465)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2023/05/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c2ae7ec");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1423304");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1419732");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1350561");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1375133");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1406120");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1418549");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1399862");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1385714");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1413586");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1416380");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 113.0.5672.63 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2461");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/02");

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

google_chrome_check_version(installs:installs, fix:'113.0.5672.63', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);

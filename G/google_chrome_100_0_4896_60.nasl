#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159304);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2022-1125",
    "CVE-2022-1127",
    "CVE-2022-1128",
    "CVE-2022-1129",
    "CVE-2022-1130",
    "CVE-2022-1131",
    "CVE-2022-1132",
    "CVE-2022-1133",
    "CVE-2022-1134",
    "CVE-2022-1135",
    "CVE-2022-1136",
    "CVE-2022-1137",
    "CVE-2022-1138",
    "CVE-2022-1139",
    "CVE-2022-1141",
    "CVE-2022-1142",
    "CVE-2022-1143",
    "CVE-2022-1144",
    "CVE-2022-1145",
    "CVE-2022-1146"
  );
  script_xref(name:"IAVA", value:"2022-A-0126-S");

  script_name(english:"Google Chrome < 100.0.4896.60 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 100.0.4896.60. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2022_03_stable-channel-update-for-desktop_29 advisory.

  - Use after free in Extensions in Google Chrome prior to 100.0.4896.60 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via specific user interaction
    and profile destruction. (CVE-2022-1145)

  - Use after free in Portals in Google Chrome prior to 100.0.4896.60 allowed a remote attacker who convinced
    a user to engage in specific user interaction to potentially exploit heap corruption via user interaction.
    (CVE-2022-1125)

  - Use after free in QR Code Generator in Google Chrome prior to 100.0.4896.60 allowed a remote attacker who
    convinced a user to engage in specific user interaction to potentially exploit heap corruption via user
    interaction. (CVE-2022-1127)

  - Inappropriate implementation in Web Share API in Google Chrome on Windows prior to 100.0.4896.60 allowed
    an attacker on the local network segment to leak cross-origin data via a crafted HTML page.
    (CVE-2022-1128)

  - Inappropriate implementation in Full Screen Mode in Google Chrome on Android prior to 100.0.4896.60
    allowed a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page.
    (CVE-2022-1129)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/03/stable-channel-update-for-desktop_29.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec40c355");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1292261");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1291891");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1301920");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1300253");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1142269");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1297404");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1303410");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1305776");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1308360");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1285601");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1280205");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1289846");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1246188");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1268541");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1303253");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1303613");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1303615");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1304145");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1304545");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1290150");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 100.0.4896.60 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1145");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1144");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/29");

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

google_chrome_check_version(installs:installs, fix:'100.0.4896.60', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);

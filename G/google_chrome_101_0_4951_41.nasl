#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160217);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2022-1477",
    "CVE-2022-1478",
    "CVE-2022-1479",
    "CVE-2022-1481",
    "CVE-2022-1482",
    "CVE-2022-1483",
    "CVE-2022-1484",
    "CVE-2022-1485",
    "CVE-2022-1486",
    "CVE-2022-1487",
    "CVE-2022-1488",
    "CVE-2022-1489",
    "CVE-2022-1490",
    "CVE-2022-1491",
    "CVE-2022-1492",
    "CVE-2022-1493",
    "CVE-2022-1494",
    "CVE-2022-1495",
    "CVE-2022-1496",
    "CVE-2022-1497",
    "CVE-2022-1498",
    "CVE-2022-1499",
    "CVE-2022-1500",
    "CVE-2022-1501"
  );
  script_xref(name:"IAVA", value:"2022-A-0183-S");

  script_name(english:"Google Chrome < 101.0.4951.41 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 101.0.4951.41. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2022_04_stable-channel-update-for-desktop_26 advisory.

  - Use after free in File Manager in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to
    potentially exploit heap corruption via specific and direct user interaction. (CVE-2022-1496)

  - Use after free in Vulkan in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1477)

  - Use after free in SwiftShader in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-1478)

  - Use after free in ANGLE in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1479)

  - Use after free in Sharing in Google Chrome on Mac prior to 101.0.4951.41 allowed a remote attacker who
    convinced a user to engage in specific user interaction to potentially exploit heap corruption via a
    crafted HTML page. (CVE-2022-1481)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/04/stable-channel-update-for-desktop_26.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e31ed7e1");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1313905");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1299261");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1305190");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1307223");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1302949");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1304987");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1314754");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1297429");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1299743");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1314616");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1304368");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1302959");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1300561");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1301840");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1305706");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1315040");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1275414");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1298122");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1301180");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1306391");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1264543");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1297138");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1000408");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1223475");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1293191");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 101.0.4951.41 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1496");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/26");

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

google_chrome_check_version(installs:installs, fix:'101.0.4951.41', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);

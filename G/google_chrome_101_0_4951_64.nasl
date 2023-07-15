##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160906);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2022-1633",
    "CVE-2022-1634",
    "CVE-2022-1635",
    "CVE-2022-1636",
    "CVE-2022-1637",
    "CVE-2022-1638",
    "CVE-2022-1639",
    "CVE-2022-1640",
    "CVE-2022-1641"
  );
  script_xref(name:"IAVA", value:"2022-A-0208-S");

  script_name(english:"Google Chrome < 101.0.4951.64 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 101.0.4951.64. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2022_05_stable-channel-update-for-desktop_10 advisory.

  - Use after free in Web UI Diagnostics in Google Chrome on Chrome OS prior to 101.0.4951.64 allowed a remote
    attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption
    via specific user interaction. (CVE-2022-1641)

  - Use after free in Sharesheet in Google Chrome on Chrome OS prior to 101.0.4951.64 allowed a remote
    attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption
    via specific user interactions. (CVE-2022-1633)

  - Use after free in Browser UI in Google Chrome prior to 101.0.4951.64 allowed a remote attacker who had
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via specific
    user interactions. (CVE-2022-1634)

  - Use after free in Permission Prompts in Google Chrome prior to 101.0.4951.64 allowed a remote attacker who
    convinced a user to engage in specific UI interactions to potentially exploit heap corruption via specific
    user interactions. (CVE-2022-1635)

  - Use after free in Performance APIs in Google Chrome prior to 101.0.4951.64 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-1636)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/05/stable-channel-update-for-desktop_10.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd5e8c42");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1316990");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1314908");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1319797");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1297283");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1311820");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1316946");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1317650");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1320592");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1305068");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 101.0.4951.64 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1641");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/10");

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

google_chrome_check_version(installs:installs, fix:'101.0.4951.64', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);

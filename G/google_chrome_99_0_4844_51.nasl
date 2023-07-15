#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158500);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/10");

  script_cve_id(
    "CVE-2022-0789",
    "CVE-2022-0790",
    "CVE-2022-0791",
    "CVE-2022-0792",
    "CVE-2022-0793",
    "CVE-2022-0794",
    "CVE-2022-0795",
    "CVE-2022-0796",
    "CVE-2022-0797",
    "CVE-2022-0798",
    "CVE-2022-0799",
    "CVE-2022-0800",
    "CVE-2022-0801",
    "CVE-2022-0802",
    "CVE-2022-0803",
    "CVE-2022-0804",
    "CVE-2022-0805",
    "CVE-2022-0806",
    "CVE-2022-0807",
    "CVE-2022-0808",
    "CVE-2022-0809"
  );
  script_xref(name:"IAVA", value:"2022-A-0096-S");

  script_name(english:"Google Chrome < 99.0.4844.51 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 99.0.4844.51. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2022_03_stable-channel-update-for-desktop advisory.

  - Use after free in Chrome OS Shell in Google Chrome on Chrome OS prior to 99.0.4844.51 allowed a remote
    attacker who convinced a user to engage in a series of user interaction to potentially exploit heap
    corruption via user interactions. (CVE-2022-0808)

  - Heap buffer overflow in ANGLE in Google Chrome prior to 99.0.4844.51 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-0789)

  - Use after free in Cast UI in Google Chrome prior to 99.0.4844.51 allowed a remote attacker who convinced a
    user to engage in specific user interaction to potentially perform a sandbox escape via a crafted HTML
    page. (CVE-2022-0790)

  - Use after free in Omnibox in Google Chrome prior to 99.0.4844.51 allowed a remote attacker who convinced a
    user to engage in specific user interactions to potentially exploit heap corruption via user interactions.
    (CVE-2022-0791)

  - Out of bounds read in ANGLE in Google Chrome prior to 99.0.4844.51 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-0792)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/03/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a12f8a5f");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1289383");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1274077");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1278322");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1285885");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1291728");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1294097");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1282782");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1295786");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1281908");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1283402");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1279188");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1242962");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1231037");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1270052");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1280233");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1264561");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1290700");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1283434");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1287364");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1292271");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1293428");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 99.0.4844.51 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0809");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0790");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/01");

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

google_chrome_check_version(installs:installs, fix:'99.0.4844.51', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);

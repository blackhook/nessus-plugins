##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161477);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2022-1853",
    "CVE-2022-1854",
    "CVE-2022-1855",
    "CVE-2022-1856",
    "CVE-2022-1857",
    "CVE-2022-1858",
    "CVE-2022-1859",
    "CVE-2022-1860",
    "CVE-2022-1861",
    "CVE-2022-1862",
    "CVE-2022-1863",
    "CVE-2022-1864",
    "CVE-2022-1865",
    "CVE-2022-1866",
    "CVE-2022-1867",
    "CVE-2022-1868",
    "CVE-2022-1869",
    "CVE-2022-1870",
    "CVE-2022-1871",
    "CVE-2022-1872",
    "CVE-2022-1873",
    "CVE-2022-1874",
    "CVE-2022-1875",
    "CVE-2022-1876"
  );
  script_xref(name:"IAVA", value:"2022-A-0220-S");

  script_name(english:"Google Chrome < 102.0.5005.61 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 102.0.5005.61. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2022_05_stable-channel-update-for-desktop_24 advisory.

  - Use after free in App Service in Google Chrome prior to 102.0.5005.61 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via a crafted Chrome
    Extension. (CVE-2022-1870)

  - Use after free in Indexed DB in Google Chrome prior to 102.0.5005.61 allowed a remote attacker to
    potentially perform a sandbox escape via a crafted HTML page. (CVE-2022-1853)

  - Use after free in ANGLE in Google Chrome prior to 102.0.5005.61 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1854)

  - Use after free in Messaging in Google Chrome prior to 102.0.5005.61 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-1855)

  - Use after free in User Education in Google Chrome prior to 102.0.5005.61 allowed an attacker who convinced
    a user to install a malicious extension to potentially exploit heap corruption via a crafted Chrome
    Extension or specific user interaction. (CVE-2022-1856)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/05/stable-channel-update-for-desktop_24.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8302386");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1324864");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1320024");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1228661");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1323239");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1227995");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1314310");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1322744");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1297209");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1316846");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1236325");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1292870");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1320624");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1289192");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1292264");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1315563");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1301203");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1309467");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1323236");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1308199");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1310461");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1305394");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1251588");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1306443");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1313600");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 102.0.5005.61 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1870");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1853");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/24");

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

google_chrome_check_version(installs:installs, fix:'102.0.5005.61', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);

#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159637);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-1305",
    "CVE-2022-1306",
    "CVE-2022-1307",
    "CVE-2022-1308",
    "CVE-2022-1309",
    "CVE-2022-1310",
    "CVE-2022-1311",
    "CVE-2022-1312",
    "CVE-2022-1313",
    "CVE-2022-1314"
  );
  script_xref(name:"IAVA", value:"2022-A-0151-S");

  script_name(english:"Google Chrome < 100.0.4896.88 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 100.0.4896.88. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2022_04_stable-channel-update-for-desktop_11 advisory.

  - Use after free in tab groups in Google Chrome prior to 100.0.4896.88 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-1313)

  - Use after free in storage in Google Chrome prior to 100.0.4896.88 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1305)

  - Inappropriate implementation in compositing in Google Chrome prior to 100.0.4896.88 allowed a remote
    attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2022-1306)

  - Inappropriate implementation in full screen in Google Chrome on Android prior to 100.0.4896.88 allowed a
    remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2022-1307)

  - Use after free in BFCache in Google Chrome prior to 100.0.4896.88 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1308)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/04/stable-channel-update-for-desktop_11.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72fe8725");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1285234");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1299287");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1301873");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1283050");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1106456");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1307610");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1310717");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1311701");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1270539");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1304658");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 100.0.4896.88 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1313");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1312");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'100.0.4896.88', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);

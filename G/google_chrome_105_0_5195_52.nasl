#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164508);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/30");

  script_cve_id(
    "CVE-2022-3038",
    "CVE-2022-3039",
    "CVE-2022-3040",
    "CVE-2022-3041",
    "CVE-2022-3042",
    "CVE-2022-3043",
    "CVE-2022-3044",
    "CVE-2022-3045",
    "CVE-2022-3046",
    "CVE-2022-3047",
    "CVE-2022-3048",
    "CVE-2022-3049",
    "CVE-2022-3050",
    "CVE-2022-3051",
    "CVE-2022-3052",
    "CVE-2022-3053",
    "CVE-2022-3054",
    "CVE-2022-3055",
    "CVE-2022-3056",
    "CVE-2022-3057",
    "CVE-2022-3058",
    "CVE-2022-3071"
  );
  script_xref(name:"IAVA", value:"2022-A-0346-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/20");

  script_name(english:"Google Chrome < 105.0.5195.52 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 105.0.5195.52. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2022_08_stable-channel-update-for-desktop_30 advisory.

  - Use after free in Sign-In Flow in Google Chrome prior to 105.0.5195.52 allowed a remote attacker who
    convinced a user to engage in specific UI interactions to potentially exploit heap corruption via crafted
    UI interaction. (CVE-2022-3058)

  - Use after free in Network Service in Google Chrome prior to 105.0.5195.52 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-3038)

  - Use after free in WebSQL in Google Chrome prior to 105.0.5195.52 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-3039, CVE-2022-3041)

  - Use after free in Layout in Google Chrome prior to 105.0.5195.52 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-3040)

  - Use after free in PhoneHub in Google Chrome on Chrome OS prior to 105.0.5195.52 allowed a remote attacker
    to potentially exploit heap corruption via a crafted HTML page. (CVE-2022-3042)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/08/stable-channel-update-for-desktop_30.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?613dc709");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1340253");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1343348");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1341539");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1345947");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1338553");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1336979");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1051198");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1339648");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1346245");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1342586");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1303308");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1316892");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1337132");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1345245");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1346154");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1267867");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1290236");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1351969");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1329460");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1336904");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1337676");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 105.0.5195.52 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3058");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3071");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/30");

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

google_chrome_check_version(installs:installs, fix:'105.0.5195.52', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);

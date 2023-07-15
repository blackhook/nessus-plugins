#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151831);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-30565",
    "CVE-2021-30566",
    "CVE-2021-30567",
    "CVE-2021-30568",
    "CVE-2021-30569",
    "CVE-2021-30571",
    "CVE-2021-30572",
    "CVE-2021-30573",
    "CVE-2021-30574",
    "CVE-2021-30575",
    "CVE-2021-30576",
    "CVE-2021-30577",
    "CVE-2021-30578",
    "CVE-2021-30579",
    "CVE-2021-30580",
    "CVE-2021-30581",
    "CVE-2021-30582",
    "CVE-2021-30583",
    "CVE-2021-30584",
    "CVE-2021-30585",
    "CVE-2021-30586",
    "CVE-2021-30587",
    "CVE-2021-30588",
    "CVE-2021-30589"
  );
  script_xref(name:"IAVA", value:"2021-A-0346-S");

  script_name(english:"Google Chrome < 92.0.4515.107 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 92.0.4515.107. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2021_07_stable-channel-update-for-desktop_20 advisory. Note that Nessus
has not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2021/07/stable-channel-update-for-desktop_20.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b961beb2");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1210985");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1202661");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1211326");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1219886");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1218707");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1101897");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1214234");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1216822");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1227315");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1213313");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1194896");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1204811");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1201074");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1207277");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1189092");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1194431");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1205981");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1179290");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1213350");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1023503");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1201032");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1204347");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1195650");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1180510");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 92.0.4515.107 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30588");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-30571");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('SMB/Google_Chrome/Installed');
installs = get_kb_list('SMB/Google_Chrome/*');

google_chrome_check_version(installs:installs, fix:'92.0.4515.107', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);

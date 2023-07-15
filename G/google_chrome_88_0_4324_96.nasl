#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(145071);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2020-16044",
    "CVE-2021-21117",
    "CVE-2021-21118",
    "CVE-2021-21119",
    "CVE-2021-21120",
    "CVE-2021-21121",
    "CVE-2021-21122",
    "CVE-2021-21123",
    "CVE-2021-21124",
    "CVE-2021-21125",
    "CVE-2021-21126",
    "CVE-2021-21127",
    "CVE-2021-21128",
    "CVE-2021-21129",
    "CVE-2021-21130",
    "CVE-2021-21131",
    "CVE-2021-21132",
    "CVE-2021-21133",
    "CVE-2021-21134",
    "CVE-2021-21135",
    "CVE-2021-21136",
    "CVE-2021-21137",
    "CVE-2021-21138",
    "CVE-2021-21139",
    "CVE-2021-21140",
    "CVE-2021-21141"
  );
  script_xref(name:"IAVA", value:"2021-A-0040-S");

  script_name(english:"Google Chrome < 88.0.4324.96 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 88.0.4324.96. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2021_01_stable-channel-update-for-desktop_19 advisory. Note that Nessus
has not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2021/01/stable-channel-update-for-desktop_19.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e7ec68ce");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1137179");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1161357");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1160534");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1160602");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1161143");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1162131");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1137247");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1131346");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1152327");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1163228");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1108126");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1115590");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1138877");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1140403");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1140410");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1140417");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1128206");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1157743");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1157800");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1157818");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1038002");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1093791");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1122487");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/937131");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1136327");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1140435");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 88.0.4324.96 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21117");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21132");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/19");

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

google_chrome_check_version(installs:installs, fix:'88.0.4324.96', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);

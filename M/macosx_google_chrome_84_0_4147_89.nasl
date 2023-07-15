#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138448);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2020-6510",
    "CVE-2020-6511",
    "CVE-2020-6512",
    "CVE-2020-6513",
    "CVE-2020-6514",
    "CVE-2020-6515",
    "CVE-2020-6516",
    "CVE-2020-6517",
    "CVE-2020-6518",
    "CVE-2020-6519",
    "CVE-2020-6520",
    "CVE-2020-6521",
    "CVE-2020-6522",
    "CVE-2020-6523",
    "CVE-2020-6524",
    "CVE-2020-6525",
    "CVE-2020-6526",
    "CVE-2020-6527",
    "CVE-2020-6528",
    "CVE-2020-6529",
    "CVE-2020-6530",
    "CVE-2020-6531",
    "CVE-2020-6533",
    "CVE-2020-6534",
    "CVE-2020-6535",
    "CVE-2020-6536"
  );
  script_xref(name:"IAVA", value:"2020-A-0314-S");

  script_name(english:"Google Chrome < 84.0.4147.89 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 84.0.4147.89. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2020_07_stable-channel-update-for-desktop advisory. Note that Nessus has
not tested for this issue but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1095560");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/986051");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1064676");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1092274");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1075734");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1052093");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1080481");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1081722");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1091670");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1074340");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/992698");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1063690");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/978779");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1016278");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1042986");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1069964");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1072412");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1073409");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1080934");
  # https://chromereleases.googleblog.com/2020/07/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96792814");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1103195");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1074317");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1084820");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1091404");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1076703");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1082755");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1092449");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1095560");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/986051");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1064676");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1092274");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1075734");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1052093");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1080481");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1081722");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1091670");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1074340");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/992698");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1063690");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/978779");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1016278");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1042986");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1069964");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1072412");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1073409");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1080934");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 84.0.4147.89 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6524");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-6522");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'84.0.4147.89', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);

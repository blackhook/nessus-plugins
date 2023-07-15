#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155353);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2021-38005",
    "CVE-2021-38006",
    "CVE-2021-38007",
    "CVE-2021-38008",
    "CVE-2021-38009",
    "CVE-2021-38010",
    "CVE-2021-38011",
    "CVE-2021-38012",
    "CVE-2021-38013",
    "CVE-2021-38014",
    "CVE-2021-38015",
    "CVE-2021-38016",
    "CVE-2021-38017",
    "CVE-2021-38018",
    "CVE-2021-38019",
    "CVE-2021-38020",
    "CVE-2021-38021",
    "CVE-2021-38022"
  );
  script_xref(name:"IAVA", value:"2021-A-0555-S");

  script_name(english:"Google Chrome < 96.0.4664.45 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 96.0.4664.45. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2021_11_stable-channel-update-for-desktop advisory.

  - Insufficient policy enforcement in iframe sandbox in Google Chrome prior to 96.0.4664.45 allowed a remote
    attacker to bypass navigation restrictions via a crafted HTML page. (CVE-2021-38017)

  - Use after free in loader in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-38005)

  - Use after free in storage foundation in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-38006, CVE-2021-38011)

  - Type confusion in V8 in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-38007, CVE-2021-38012)

  - Use after free in media in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-38008)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2021/11/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8cf8e77e");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1254189");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1263620");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1260649");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1240593");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1241091");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1264477");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1268274");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1262791");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1242392");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1248567");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/957553");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1244289");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1256822");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1197889");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1251179");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1259694");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1233375");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1248862");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 96.0.4664.45 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38017");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-38013");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'96.0.4664.45', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);

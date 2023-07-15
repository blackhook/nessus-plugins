#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156861);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2022-0289",
    "CVE-2022-0290",
    "CVE-2022-0291",
    "CVE-2022-0292",
    "CVE-2022-0293",
    "CVE-2022-0294",
    "CVE-2022-0295",
    "CVE-2022-0296",
    "CVE-2022-0297",
    "CVE-2022-0298",
    "CVE-2022-0300",
    "CVE-2022-0301",
    "CVE-2022-0302",
    "CVE-2022-0304",
    "CVE-2022-0305",
    "CVE-2022-0306",
    "CVE-2022-0307",
    "CVE-2022-0308",
    "CVE-2022-0309",
    "CVE-2022-0310",
    "CVE-2022-0311"
  );
  script_xref(name:"IAVA", value:"2022-A-0042-S");

  script_name(english:"Google Chrome < 97.0.4692.99 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 97.0.4692.99. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2022_01_stable-channel-update-for-desktop_19 advisory.

  - Use after free in Data Transfer in Google Chrome on Chrome OS prior to 97.0.4692.99 allowed a remote
    attacker who convinced a user to engage in specific user interaction to potentially exploit heap
    corruption via a crafted HTML page. (CVE-2022-0308)

  - Use after free in Safe browsing in Google Chrome prior to 97.0.4692.99 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-0289)

  - Use after free in Site isolation in Google Chrome prior to 97.0.4692.99 allowed a remote attacker to
    potentially perform a sandbox escape via a crafted HTML page. (CVE-2022-0290)

  - Inappropriate implementation in Storage in Google Chrome prior to 97.0.4692.99 allowed a remote attacker
    who had compromised the renderer process to bypass site isolation via a crafted HTML page. (CVE-2022-0291)

  - Inappropriate implementation in Fenced Frames in Google Chrome prior to 97.0.4692.99 allowed a remote
    attacker who had compromised the renderer process to bypass navigation restrictions via a crafted HTML
    page. (CVE-2022-0292)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/01/stable-channel-update-for-desktop_19.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9140b07");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1284367");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1260007");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1281084");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1270358");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1283371");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1273017");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1278180");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1283375");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1274316");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1212957");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1275438");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1276331");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1278613");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1281979");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1282118");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1282354");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1283198");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1281881");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1282480");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1240472");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1283805");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1283807");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 97.0.4692.99 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0311");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0290");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'97.0.4692.99', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);

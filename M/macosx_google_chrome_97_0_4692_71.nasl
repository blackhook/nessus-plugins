#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156461);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2022-0096",
    "CVE-2022-0097",
    "CVE-2022-0098",
    "CVE-2022-0099",
    "CVE-2022-0100",
    "CVE-2022-0101",
    "CVE-2022-0102",
    "CVE-2022-0103",
    "CVE-2022-0104",
    "CVE-2022-0105",
    "CVE-2022-0106",
    "CVE-2022-0107",
    "CVE-2022-0108",
    "CVE-2022-0109",
    "CVE-2022-0110",
    "CVE-2022-0111",
    "CVE-2022-0112",
    "CVE-2022-0113",
    "CVE-2022-0114",
    "CVE-2022-0115",
    "CVE-2022-0116",
    "CVE-2022-0117",
    "CVE-2022-0118",
    "CVE-2022-0120",
    "CVE-2022-0337"
  );
  script_xref(name:"IAVA", value:"2022-A-0001-S");

  script_name(english:"Google Chrome < 97.0.4692.71 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 97.0.4692.71. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2022_01_stable-channel-update-for-desktop advisory.

  - Use after free in File Manager API in Google Chrome on Chrome OS prior to 97.0.4692.71 allowed an attacker
    who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted
    HTML page. (CVE-2022-0107)

  - Use after free in Storage in Google Chrome prior to 97.0.4692.71 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-0096)

  - Inappropriate implementation in DevTools in Google Chrome prior to 97.0.4692.71 allowed an attacker who
    convinced a user to install a malicious extension to to potentially allow extension to escape the sandbox
    via a crafted HTML page. (CVE-2022-0097)

  - Use after free in Screen Capture in Google Chrome on Chrome OS prior to 97.0.4692.71 allowed an attacker
    who convinced a user to perform specific user gestures to potentially exploit heap corruption via specific
    user gestures. (CVE-2022-0098)

  - Use after free in Sign-in in Google Chrome prior to 97.0.4692.71 allowed a remote attacker who convinced a
    user to perform specific user gestures to potentially exploit heap corruption via specific user gesture.
    (CVE-2022-0099)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/01/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ffc44e4");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1275020");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1117173");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1273609");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1245629");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1238209");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1249426");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1260129");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1272266");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1273661");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1274376");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1278960");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1248438");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1248444");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1261689");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1237310");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1241188");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1255713");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1039885");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1267627");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1268903");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1272250");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1115847");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1238631");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1262953");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 97.0.4692.71 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0115");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0097");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/04");

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

google_chrome_check_version(fix:'97.0.4692.71', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);

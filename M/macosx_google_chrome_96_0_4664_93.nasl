#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155866);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/11");

  script_cve_id(
    "CVE-2021-4052",
    "CVE-2021-4053",
    "CVE-2021-4054",
    "CVE-2021-4055",
    "CVE-2021-4056",
    "CVE-2021-4057",
    "CVE-2021-4058",
    "CVE-2021-4059",
    "CVE-2021-4061",
    "CVE-2021-4062",
    "CVE-2021-4063",
    "CVE-2021-4064",
    "CVE-2021-4065",
    "CVE-2021-4066",
    "CVE-2021-4067",
    "CVE-2021-4068",
    "CVE-2021-4078",
    "CVE-2021-4079"
  );
  script_xref(name:"IAVA", value:"2021-A-0568-S");

  script_name(english:"Google Chrome < 96.0.4664.93 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 96.0.4664.93. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2021_12_stable-channel-update-for-desktop advisory.

  - Out of bounds write in WebRTC in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to
    potentially exploit heap corruption via crafted WebRTC packets. (CVE-2021-4079)

  - Use after free in web apps in Google Chrome prior to 96.0.4664.93 allowed an attacker who convinced a user
    to install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension.
    (CVE-2021-4052)

  - Use after free in UI in Google Chrome on Linux prior to 96.0.4664.93 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-4053)

  - Incorrect security UI in autofill in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to
    perform domain spoofing via a crafted HTML page. (CVE-2021-4054)

  - Heap buffer overflow in extensions in Google Chrome prior to 96.0.4664.93 allowed an attacker who
    convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted
    Chrome Extension. (CVE-2021-4055)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2021/12/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cd0fa03");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1267661");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1267791");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1239760");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1266510");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1260939");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1262183");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1267496");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1270990");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1271456");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1272403");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1273176");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1273197");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1273674");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1274499");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1274641");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1265197");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 96.0.4664.93 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4079");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/06");

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

google_chrome_check_version(fix:'96.0.4664.93', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);

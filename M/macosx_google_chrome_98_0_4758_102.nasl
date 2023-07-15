#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158050);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/03");

  script_cve_id(
    "CVE-2022-0603",
    "CVE-2022-0604",
    "CVE-2022-0605",
    "CVE-2022-0606",
    "CVE-2022-0607",
    "CVE-2022-0608",
    "CVE-2022-0609",
    "CVE-2022-0610"
  );
  script_xref(name:"IAVA", value:"2022-A-0086-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/01");

  script_name(english:"Google Chrome < 98.0.4758.102 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 98.0.4758.102. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2022_02_stable-channel-update-for-desktop_14 advisory.

  - Inappropriate implementation in Gamepad API in Google Chrome prior to 98.0.4758.102 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (CVE-2022-0610)

  - Use after free in File Manager in Google Chrome on Chrome OS prior to 98.0.4758.102 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (CVE-2022-0603)

  - Heap buffer overflow in Tab Groups in Google Chrome prior to 98.0.4758.102 allowed an attacker who
    convinced a user to install a malicious extension and engage in specific user interaction to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-0604)

  - Use after free in Webstore API in Google Chrome prior to 98.0.4758.102 allowed an attacker who convinced a
    user to install a malicious extension and convinced a user to enage in specific user interaction to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-0605)

  - Use after free in ANGLE in Google Chrome prior to 98.0.4758.102 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-0606)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/02/stable-channel-update-for-desktop_14.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a5bae0d");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1290008");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1273397");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1286940");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1288020");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1250655");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1270333");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1296150");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1285449");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 98.0.4758.102 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0610");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/14");

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

google_chrome_check_version(fix:'98.0.4758.102', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);

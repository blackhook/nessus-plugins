#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153255);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2021-30625",
    "CVE-2021-30626",
    "CVE-2021-30627",
    "CVE-2021-30628",
    "CVE-2021-30629",
    "CVE-2021-30630",
    "CVE-2021-30632",
    "CVE-2021-30633"
  );
  script_xref(name:"IAVA", value:"2021-A-0411-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"Google Chrome < 93.0.4577.82 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 93.0.4577.82. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2021_09_stable-channel-update-for-desktop advisory.

  - Use after free in Indexed DB API in Google Chrome prior to 93.0.4577.82 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2021-30633)

  - Use after free in Selection API in Google Chrome prior to 93.0.4577.82 allowed a remote attacker who
    convinced the user the visit a malicious website to potentially exploit heap corruption via a crafted HTML
    page. (CVE-2021-30625)

  - Out of bounds memory access in ANGLE in Google Chrome prior to 93.0.4577.82 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-30626)

  - Type confusion in Blink layout in Google Chrome prior to 93.0.4577.82 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-30627)

  - Stack buffer overflow in ANGLE in Google Chrome prior to 93.0.4577.82 allowed a remote attacker to
    potentially exploit stack corruption via a crafted HTML page. (CVE-2021-30628)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2021/09/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc94c497");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1237533");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1241036");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1245786");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1241123");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1243646");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1244568");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1246932");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1247763");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1247766");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 93.0.4577.82 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30633");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/14");

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
var installs = get_kb_list('SMB/Google_Chrome/*');

google_chrome_check_version(installs:installs, fix:'93.0.4577.82', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);

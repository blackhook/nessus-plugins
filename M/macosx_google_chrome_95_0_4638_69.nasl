#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154705);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-37997",
    "CVE-2021-37998",
    "CVE-2021-37999",
    "CVE-2021-38000",
    "CVE-2021-38001",
    "CVE-2021-38002",
    "CVE-2021-38003",
    "CVE-2021-38004"
  );
  script_xref(name:"IAVA", value:"2021-A-0522-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"Google Chrome < 95.0.4638.69 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 95.0.4638.69. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2021_10_stable-channel-update-for-desktop_28 advisory.

  - Inappropriate implementation in V8 in Google Chrome prior to 95.0.4638.69 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-38003)

  - Use after free in Sign-In in Google Chrome prior to 95.0.4638.69 allowed a remote attacker who convinced a
    user to sign into Chrome to potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37997)

  - Use after free in Garbage Collection in Google Chrome prior to 95.0.4638.69 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37998)

  - Insufficient data validation in New Tab Page in Google Chrome prior to 95.0.4638.69 allowed a remote
    attacker to inject arbitrary scripts or HTML in a new browser tab via a crafted HTML page.
    (CVE-2021-37999)

  - Insufficient validation of untrusted input in Intents in Google Chrome on Android prior to 95.0.4638.69
    allowed a remote attacker to arbitrarily browser to a malicious URL via a crafted HTML page.
    (CVE-2021-38000)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2021/10/stable-channel-update-for-desktop_28.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9b4b94a");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1259864");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1259587");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1251541");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1249962");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1260577");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1260940");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1263462");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 95.0.4638.69 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38003");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-38002");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'95.0.4638.69', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);

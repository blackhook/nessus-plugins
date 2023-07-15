#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167100);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2022-3885",
    "CVE-2022-3886",
    "CVE-2022-3887",
    "CVE-2022-3888",
    "CVE-2022-3889",
    "CVE-2022-3890"
  );
  script_xref(name:"IAVA", value:"2022-A-0482-S");

  script_name(english:"Google Chrome < 107.0.5304.110 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 107.0.5304.110. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2022_11_stable-channel-update-for-desktop advisory.

  - Use after free in WebCodecs in Google Chrome prior to 107.0.5304.106 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2022-3888)

  - Use after free in V8 in Google Chrome prior to 107.0.5304.106 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2022-3885)

  - Use after free in Speech Recognition in Google Chrome prior to 107.0.5304.106 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2022-3886)

  - Use after free in Web Workers in Google Chrome prior to 107.0.5304.106 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2022-3887)

  - Type confusion in V8 in Google Chrome prior to 107.0.5304.106 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2022-3889)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/11/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52007474");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1377816");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1372999");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1372695");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1375059");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1380063");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1380083");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 107.0.5304.110 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3888");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3890");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'107.0.5304.110', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);

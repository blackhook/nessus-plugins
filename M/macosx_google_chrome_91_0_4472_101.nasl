#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150431);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/30");

  script_cve_id(
    "CVE-2021-30544",
    "CVE-2021-30545",
    "CVE-2021-30546",
    "CVE-2021-30547",
    "CVE-2021-30548",
    "CVE-2021-30549",
    "CVE-2021-30550",
    "CVE-2021-30551",
    "CVE-2021-30552",
    "CVE-2021-30553"
  );
  script_xref(name:"IAVA", value:"2021-A-0293-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"Google Chrome < 91.0.4472.101 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 91.0.4472.101. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2021_06_stable-channel-update-for-desktop advisory. Note that Nessus has
not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2021/06/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30538e38");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1212618");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1201031");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1206911");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1210414");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1210487");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1212498");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1212500");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1216437");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1200679");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1209769");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 91.0.4472.101 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30553");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'91.0.4472.101', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);

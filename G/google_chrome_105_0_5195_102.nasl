#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164656);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2022-3075");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/29");
  script_xref(name:"IAVA", value:"2022-A-0351-S");

  script_name(english:"Google Chrome < 105.0.5195.102 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 105.0.5195.102. It is, therefore, affected
by a vulnerability as referenced in the 2022_09_stable-channel-update-for-desktop advisory.

  - Insufficient data validation in Mojo in Google Chrome prior to 105.0.5195.102 allowed a remote attacker
    who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2022-3075)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/09/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84ba03a1");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1358134");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 105.0.5195.102 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3075");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('SMB/Google_Chrome/Installed');
var installs = get_kb_list('SMB/Google_Chrome/*');

google_chrome_check_version(installs:installs, fix:'105.0.5195.102', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);

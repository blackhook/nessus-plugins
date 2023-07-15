#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176676);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");

  script_cve_id("CVE-2023-3079");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/28");
  script_xref(name:"IAVA", value:"2023-A-0276-S");

  script_name(english:"Google Chrome < 114.0.5735.106 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 114.0.5735.106. It is, therefore, affected
by a vulnerability as referenced in the 2023_06_stable-channel-update-for-desktop advisory.

  - Type Confusion in V8. (CVE-2023-3079)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1450481");
  # https://chromereleases.googleblog.com/2023/06/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef5085a5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 114.0.5735.106 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3079");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'114.0.5735.106', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);

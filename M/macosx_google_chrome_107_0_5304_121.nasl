#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168182);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/08");

  script_cve_id("CVE-2022-4135");
  script_xref(name:"IAVA", value:"2022-A-0482-S");
  script_xref(name:"IAVA", value:"2022-A-0501-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/12/19");

  script_name(english:"Google Chrome < 107.0.5304.121 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 107.0.5304.121. It is, therefore, affected
by a vulnerability as referenced in the 2022_11_stable-channel-update-for-desktop_24 advisory.

  - Heap buffer overflow in GPU. (CVE-2022-4135)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2022/11/stable-channel-update-for-desktop_24.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eea42332");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1392715");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 107.0.5304.121 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4135");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/24");

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

google_chrome_check_version(fix:'107.0.5304.121', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);

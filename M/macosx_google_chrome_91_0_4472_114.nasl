#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150855);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-30554",
    "CVE-2021-30555",
    "CVE-2021-30556",
    "CVE-2021-30557"
  );
  script_xref(name:"IAVA", value:"2021-A-0293-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"Google Chrome < 91.0.4472.114 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 91.0.4472.114. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2021_06_stable-channel-update-for-desktop_17 advisory. Note that Nessus
has not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2021/06/stable-channel-update-for-desktop_17.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4d03a3a");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1219857");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1215029");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1212599");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1202102");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 91.0.4472.114 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30557");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/17");

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

google_chrome_check_version(fix:'91.0.4472.114', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);

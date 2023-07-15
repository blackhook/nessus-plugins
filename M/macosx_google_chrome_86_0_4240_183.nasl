##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142208);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-16004",
    "CVE-2020-16005",
    "CVE-2020-16006",
    "CVE-2020-16007",
    "CVE-2020-16008",
    "CVE-2020-16009",
    "CVE-2020-16011"
  );
  script_xref(name:"IAVA", value:"2020-A-0486-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0124");

  script_name(english:"Google Chrome < 86.0.4240.183 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 86.0.4240.183. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2020_11_stable-channel-update-for-desktop advisory. Note that Nessus has
not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2020/11/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74346d34");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1138911");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1139398");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1133527");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1125018");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1134107");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1143772");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1144489");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 86.0.4240.183 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16011");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'86.0.4240.183', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);

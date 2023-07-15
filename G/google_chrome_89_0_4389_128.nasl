#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148487);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2021-21206", "CVE-2021-21220");
  script_xref(name:"IAVA", value:"2021-A-0176-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"Google Chrome < 89.0.4389.128 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 89.0.4389.128. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2021_04_stable-channel-update-for-desktop advisory. Note that Nessus
has not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2021/04/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9531cc08");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1196781");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1196683");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 89.0.4389.128 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21220");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Google Chrome versions before 89.0.4389.128 V8 XOR Typer Out-Of-Bounds Access RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/13");

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
installs = get_kb_list('SMB/Google_Chrome/*');

google_chrome_check_version(installs:installs, fix:'89.0.4389.128', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);

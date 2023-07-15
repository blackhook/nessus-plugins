#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118152);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2018-5179",
    "CVE-2018-17462",
    "CVE-2018-17463",
    "CVE-2018-17464",
    "CVE-2018-17465",
    "CVE-2018-17466",
    "CVE-2018-17467",
    "CVE-2018-17468",
    "CVE-2018-17469",
    "CVE-2018-17470",
    "CVE-2018-17471",
    "CVE-2018-17472",
    "CVE-2018-17473",
    "CVE-2018-17474",
    "CVE-2018-17475",
    "CVE-2018-17476",
    "CVE-2018-17477"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"Google Chrome < 70.0.3538.67 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by
multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is
prior to 70.0.3538.67. It is, therefore, affected by multiple
vulnerabilities as noted in Google Chrome stable channel update
release notes for 2018/10/16. Please refer to the release notes for
additional information. Note that Nessus has not attempted to exploit
these issues but has instead relied only on the application's self-
reported version number.");
  # https://chromereleases.googleblog.com/2018/10/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c8f5c86");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 70.0.3538.67 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-17474");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-17472");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Google Chrome 67, 68 and 69 Object.create exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'70.0.3538.67', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);

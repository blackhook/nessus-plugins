#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119557);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2018-17480",
    "CVE-2018-17481",
    "CVE-2018-18335",
    "CVE-2018-18336",
    "CVE-2018-18337",
    "CVE-2018-18338",
    "CVE-2018-18339",
    "CVE-2018-18340",
    "CVE-2018-18341",
    "CVE-2018-18342",
    "CVE-2018-18343",
    "CVE-2018-18344",
    "CVE-2018-18345",
    "CVE-2018-18346",
    "CVE-2018-18347",
    "CVE-2018-18348",
    "CVE-2018-18349",
    "CVE-2018-18350",
    "CVE-2018-18351",
    "CVE-2018-18352",
    "CVE-2018-18353",
    "CVE-2018-18354",
    "CVE-2018-18355",
    "CVE-2018-18356",
    "CVE-2018-18357",
    "CVE-2018-18358",
    "CVE-2018-18359"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"Google Chrome < 71.0.3578.80 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by
multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is
prior to 71.0.3578.80. It is, therefore, affected by multiple
vulnerabilities as noted in Google Chrome stable channel update
release notes for 2018/12/04. Please refer to the release notes for
additional information. Note that Nessus has not attempted to exploit
these issues but has instead relied only on the application's self-
reported version number.");
  # https://chromereleases.googleblog.com/2018/12/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?084b0392");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 71.0.3578.80 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18359");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/10");

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

google_chrome_check_version(fix:'71.0.3578.80', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);

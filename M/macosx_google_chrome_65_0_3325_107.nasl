#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(107221);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/08");

  script_cve_id(
    "CVE-2017-11215",
    "CVE-2017-11225",
    "CVE-2018-6057",
    "CVE-2018-6060",
    "CVE-2018-6061",
    "CVE-2018-6062",
    "CVE-2018-6063",
    "CVE-2018-6064",
    "CVE-2018-6065",
    "CVE-2018-6066",
    "CVE-2018-6067",
    "CVE-2018-6068",
    "CVE-2018-6069",
    "CVE-2018-6070",
    "CVE-2018-6071",
    "CVE-2018-6072",
    "CVE-2018-6073",
    "CVE-2018-6074",
    "CVE-2018-6075",
    "CVE-2018-6076",
    "CVE-2018-6077",
    "CVE-2018-6078",
    "CVE-2018-6079",
    "CVE-2018-6080",
    "CVE-2018-6081",
    "CVE-2018-6082",
    "CVE-2018-6083"
  );
  script_bugtraq_id(101837);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"Google Chrome < 65.0.3325.146 Multiple Vulnerabilities (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is prior
to 65.0.3325.146. It is, therefore, affected by multiple unspecified
vulnerabilities as noted in Chrome stable channel update release notes
for March 6th, 2018. Please refer to the release notes for additional
information.

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2018/03/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?68129919");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 65.0.3325.146 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11225");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("MacOSX/Google Chrome/Installed");

google_chrome_check_version(fix:'65.0.3325.146', severity:SECURITY_HOLE);

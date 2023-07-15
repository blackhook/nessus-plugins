#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119938);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/04");

  script_cve_id(
    "CVE-2018-0734",
    "CVE-2018-0735",
    "CVE-2018-5407",
    "CVE-2018-12116",
    "CVE-2018-12120",
    "CVE-2018-12121",
    "CVE-2018-12122",
    "CVE-2018-12123"
  );
  script_bugtraq_id(
    105750,
    105758,
    105897,
    106040,
    106043
  );

  script_name(english:"Node.js Multiple Vulnerabilities (November 2018 Security Releases)");
  script_summary(english:"Checks the Node.js version.");

  script_set_attribute(attribute:"synopsis", value:
"Node.js - JavaScript run-time environment is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Node.js installed on the remote host is 6.x prior to 6.15.0, 8.x prior to 8.14.0 or 10.x prior to
10.14.0 or 11.x prior to 11.3.0. It is, therefore, affected by multiple vulnerabilities.

  - OpenSSL Timing vulnerability in DSA signature generation (CVE-2018-0734).

  - OpenSSL Timing vulnerability in ECDSA signature generation (CVE-2018-0735).

  - OpenSSL Microarchitecture timing vulnerability in ECC scalar multiplication (CVE-2018-5407).

  - Debugger port 5858 listens on any interface by default  CVE-2018-12120).

  - Denial of Service with large HTTP headers (CVE-2018-12121).

  - Slowloris HTTP Denial of Service (CVE-2018-12122).

  - Hostname spoofing in URL parser for javascript protocol (CVE-2018-12123).

  - HTTP request splitting (CVE-2018-12116).

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://nodejs.org/en/blog/vulnerability/november-2018-security-releases/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fdc3667d");
  script_set_attribute(attribute:"solution", value:
"Upgrade Node.js to 6.15 / 8.14.0 / 10.14.0 / 11.3.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12120");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nodejs:node.js");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nodejs_win_installed.nbin", "macosx_nodejs_installed.nbin");
  script_require_keys("installed_sw/Node.js");

  exit(0);
}

include('vcf.inc');

win_local = FALSE;
if (get_kb_item('SMB/Registry/Enumerated')) win_local = TRUE;

app_info = vcf::get_app_info(app:'Node.js', win_local:win_local);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '6.0.0', 'fixed_version' : '6.15.0' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.14.0' },
  { 'min_version' : '10.0.0', 'fixed_version' : '10.14.0' },
  { 'min_version' : '11.0.0', 'fixed_version' : '11.3.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

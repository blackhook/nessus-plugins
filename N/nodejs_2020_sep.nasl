#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140795);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2020-8201", "CVE-2020-8251", "CVE-2020-8252");
  script_xref(name:"IAVB", value:"2020-B-0057-S");

  script_name(english:"Node.js Multiple Vulnerabilities (September 2020 Security Releases)");

  script_set_attribute(attribute:"synopsis", value:
"Node.js - JavaScript run-time environment is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Node.js installed on the remote host is prior to 10.22.1 or 12.18.4 or 14.11.0. It is, therefore,
affected by multiple vulnerabilities as referenced in the september-2020-security-releases advisory.

  - Affected Node.js versions converted carriage returns in HTTP request headers to a hyphen before parsing.
    This can lead to HTTP Request Smuggling as it is a non-standard interpretation of the header.
    (CVE-2020-8201)

  - Node.js is vulnerable to HTTP denial of service (DOS) attacks based on delayed requests submission which
    can make the server unable to accept new connections. The fix a new http.Server option called requestTimeout
    with a default value of 0 which means it is disabled by default. This should be set when Node.js is used
    as an edge server. (CVE-2020-8251)

  - libuv's realpath implementation incorrectly determined the buffer size which can result in a buffer overflow
    if the resolved path is longer than 256 bytes. (CVE-2020-8252)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://nodejs.org/en/blog/vulnerability/september-2020-security-releases/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64b99430");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Node.js version 10.22.1 / 12.18.4 / 14.11.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8201");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-8252");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nodejs:node.js");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '10.0.0', 'fixed_version' : '10.22.1' },
  { 'min_version' : '12.0.0', 'fixed_version' : '12.18.4' },
  { 'min_version' : '14.0.0', 'fixed_version' : '14.11.0' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);

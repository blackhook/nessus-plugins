#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167024);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/22");

  script_cve_id("CVE-2022-3602", "CVE-2022-3786", "CVE-2022-43548");
  script_xref(name:"IAVB", value:"2022-B-0047-S");
  script_xref(name:"CEA-ID", value:"CEA-2022-0036");

  script_name(english:"Node.js 14.x < 14.21.1 / 16.x < 16.18.1 / 18.x < 18.12.1 / 19.x < 19.0.1 Multiple Vulnerabilities (Nov 3 2022 Security Releases).");

  script_set_attribute(attribute:"synopsis", value:
"Node.js - JavaScript run-time environment is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Node.js installed on the remote host is prior to 14.21.1, 16.18.1, 18.12.1, 19.0.1. It is, therefore,
affected by multiple vulnerabilities as referenced in the Nov 3 2022 Security Releases advisory.

  - A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint
    checking. Note that this occurs after certificate chain signature verification and requires either a CA to
    have signed the malicious certificate or for the application to continue certificate verification despite
    failure to construct a path to a trusted issuer. An attacker can craft a malicious email address to
    overflow four attacker-controlled bytes on the stack. This buffer overflow could result in a crash
    (causing a denial of service) or potentially remote code execution. Impacts: (CVE-2022-3602)

  - A buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint
    checking. Note that this occurs after certificate chain signature verification and requires either a CA to
    have signed a malicious certificate or for an application to continue certificate verification despite
    failure to construct a path to a trusted issuer. An attacker can craft a malicious email address in a
    certificate to overflow an arbitrary number of bytes containing the . character (decimal 46) on the stack.
    This buffer overflow could result in a crash (causing a denial of service). In a TLS client, this can be
    triggered by connecting to a malicious server. In a TLS server, this can be triggered if the server
    requests client authentication and a malicious client connects. OpenSSL versions 3.0.0 to 3.0.6 are
    vulnerable to this issue. Impacts: (CVE-2022-3786)

  - The Node.js rebinding protector for --inspect still allows invalid IP address, specifically, the octal
    format. An example of an octal IP address is 1.09.0.0, the 09 octet is invalid because 9 is not a number
    in the base 8 number system. Browsers such as Firefox (tested on latest version m105) will still attempt
    to resolve this invalid octal address via DNS. When combined with an active --inspect session, such as
    when using VSCode, an attacker can perform DNS rebinding and execute arbitrary code Thank you to
    @haxatron1 for reporting this vulnerability. Impacts: (CVE-2022-43548)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://nodejs.org/en/blog/vulnerability/november-2022-security-releases/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01a243d6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Node.js version 14.21.1 / 16.18.1 / 18.12.1 / 19.0.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-43548");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nodejs:node.js");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nodejs_win_installed.nbin");
  script_require_keys("installed_sw/Node.js");

  exit(0);
}

include('vcf.inc');

var win_local = FALSE;
var os = get_kb_item_or_exit('Host/OS');
if ('windows' >< tolower(os)) win_local = TRUE;
var app_info = vcf::get_app_info(app:'Node.js', win_local:win_local);
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '14.0.0', 'fixed_version' : '14.21.1' },
  { 'min_version' : '16.0.0', 'fixed_version' : '16.18.1' },
  { 'min_version' : '18.0.0', 'fixed_version' : '18.12.1' },
  { 'min_version' : '19.0.0', 'fixed_version' : '19.0.1' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

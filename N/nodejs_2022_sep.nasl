#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165633);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-32212",
    "CVE-2022-32213",
    "CVE-2022-32215",
    "CVE-2022-32222",
    "CVE-2022-35255",
    "CVE-2022-35256"
  );
  script_xref(name:"IAVB", value:"2022-B-0036-S");

  script_name(english:"Node.js 14.x < 14.20.1 / 16.x < 16.17.1 / 18.x < 18.9.1 Multiple Vulnerabilities (September 23rd 2022 Security Releases).");

  script_set_attribute(attribute:"synopsis", value:
"Node.js - JavaScript run-time environment is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Node.js installed on the remote host is prior to 14.20.1, 16.17.1, 18.9.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the September 23rd 2022 Security Releases advisory.

  - The fix for CVE-2022-32212, covered the cases for routable IP addresses, however, there exists a specific
    behavior on macOS devices when handling the http://0.0.0.0 URL that allows an attacker-controlled DNS
    server to bypass the DNS rebinding protection by resolving hosts in the .local domain. An attacker-
    controlled DNS server can, resolve <Computer Name>.local to any arbitrary IP address, and consequently
    cause the victim's browser to load arbitrary content at http://0.0.0.0. This allows the attacker to bypass
    the DNS rebinding protection. Thank you, to Zeyu Zhang (@zeyu2001) for reporting this vulnerability and
    thank you Rafael Gonzaga for fixing it. Impacts: (CVE-2022-32212)

  - Due to an incomplete fix for CVE-2022-32215, the llhttp parser in the http module in Node.js v16.16.0 and
    18.7.0 still does not correctly handle multi-line Transfer-Encoding headers. This can lead to HTTP Request
    Smuggling (HRS). Thank you, Liav Gutman of the JFrog CSO Team for reporting this vulnerability and thank
    you Paolo Insogna for fixing it. Impacts: (CVE-2022-32215)

  - The fix for CVE-2022-32213 can be bypassed using an obs-fold, which the Node.js HTTP parser supports. If
    the Node.js HTTP module is used as a proxy, then it incorrectly parses the transfer-encoding header as
    indicative of chunked request, while folding the headers and hence forwarding Transfer-Encoding: chunked
    abc which is not a valid transfer-encoding header to the downstream server. As such this can lead to HTTP
    request smuggling as indicated by CVE-2022-32213. Thank you, Haxatron for reporting this vulnerability.
    Impacts: (CVE-2022-32213)

  - The llhttp parser in the http module in Node.js v18.7.0 does not correctly handle header fields that are
    not terminated with CLRF. This may result in HTTP Request Smuggling. Thank you, VVX7 for reporting this
    vulnerability. Impacts: (CVE-2022-35256)

  - In Node.js 18 and later, at startup, the process attempts to read
    /home/iojs/build/ws/out/Release/obj.target/deps/openssl/openssl.cnf on MacOS which ordinarily doesn't
    exist. The attack would be an attacker with access to a shared MacOS host with a self-chosen username
    (iojs) being able to affect the OpenSSF configuration of other users. Thank you, Michael Dawson for
    reporting (and fixing!) this vulnerability. Impacts: (CVE-2022-32222)

  - Node.js made calls to EntropySource() in SecretKeyGenTraits::DoKeyGen() in src/crypto/crypto_keygen.cc.
    However, it does not check the return value, it assumes EntropySource() always succeeds, but it can (and
    sometimes will) fail. Thank you, Ben Noordhuis for reporting (and fixing!) this vulnerability. Impacts:
    (CVE-2022-35255)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://nodejs.org/en/blog/vulnerability/september-2022-security-releases/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b6fbe18");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Node.js version 14.20.1 / 16.17.1 / 18.9.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-35255");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/03");

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
  { 'min_version' : '14.0.0', 'fixed_version' : '14.20.1' },
  { 'min_version' : '16.0.0', 'fixed_version' : '16.17.1' },
  { 'min_version' : '18.0.0', 'fixed_version' : '18.9.1' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

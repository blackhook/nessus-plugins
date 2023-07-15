#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165634);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-2097",
    "CVE-2022-32212",
    "CVE-2022-32213",
    "CVE-2022-32214",
    "CVE-2022-32215",
    "CVE-2022-32222",
    "CVE-2022-32223"
  );
  script_xref(name:"IAVB", value:"2022-B-0036-S");

  script_name(english:"Node.js 14.x < 14.20.0 / 16.x < 16.16.0 / 18.x < 18.5.0 Multiple Vulnerabilities (July 7th 2022 Security Releases).");

  script_set_attribute(attribute:"synopsis", value:
"Node.js - JavaScript run-time environment is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Node.js installed on the remote host is prior to 14.20.0, 16.16.0, 18.5.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the July 7th 2022 Security Releases advisory.

  - The llhttp parser in the http module does not correctly parse and validate Transfer-Encoding headers. This
    can lead to HTTP Request Smuggling (HRS). More details will be available at CVE-2022-32213 after
    publication. Thank you to Zeyu Zhang (@zeyu2001) for reporting this vulnerability. Impacts:
    (CVE-2022-32213)

  - The llhttp parser in the http module does not strictly use the CRLF sequence to delimit HTTP requests.
    This can lead to HTTP Request Smuggling (HRS). More details will be available at CVE-2022-32214 after
    publication. Thank you to Zeyu Zhang (@zeyu2001) for reporting this vulnerability. Impacts:
    (CVE-2022-32214)

  - The llhttp parser in the http module does not correctly handle multi-line Transfer-Encoding headers. This
    can lead to HTTP Request Smuggling (HRS). More details will be available at CVE-2022-32215 after
    publication. Thank you to Zeyu Zhang (@zeyu2001) for reporting this vulnerability. Impacts:
    (CVE-2022-32215)

  - The IsAllowedHost check can easily be bypassed because IsIPAddress does not properly check if an IP
    address is invalid or not. When an invalid IPv4 address is provided (for instance 10.0.2.555 is provided),
    browsers (such as Firefox) will make DNS requests to the DNS server, providing a vector for an attacker-
    controlled DNS server or a MITM who can spoof DNS responses to perform a rebinding attack and hence
    connect to the WebSocket debugger, allowing for arbitrary code execution. This is a bypass of
    CVE-2021-22884. More details will be available at CVE-2022-32212 after publication. Thank you to Axel
    Chong for reporting this vulnerability. Impacts: (CVE-2022-32212)

  - This vulnerability can be exploited if the victim has the following dependencies on Windows machine:
    Whenever the above conditions are present, node.exe will search for providers.dll in the current user
    directory. After that, node.exe will try to search for providers.dll by the DLL Search Order in Windows.
    It is possible for an attacker to place the malicious file providers.dll under a variety of paths and
    exploit this vulnerability. More details will be available at CVE-2022-32223 after publication. Thank you
    to Yakir Kadkoda from Aqua Security for reporting this vulnerability. Impacts: Note: Node.js can use an
    OpenSSL configuration file by specifying the environment variable OPENSSL_CONF, or using the command line
    option --openssl-conf, and if none of those are specified will default to reading the default OpenSSL
    configuration file openssl.cnf. Node.js will only read a section that is by default named nodejs_conf. If
    your installation was using the default openssl.cnf file and is affected by this breaking change you can
    fall back to the previous behavior by: (CVE-2022-32223)

  - When Node.js starts on linux based systems, it attempts to read
    /home/iojs/build/ws/out/Release/obj.target/deps/openssl/openssl.cnf, which ordinarily doesn't exist. On
    some shared systems an attacker may be able create this file and therefore affect the default OpenSSL
    configuration for other users. Thank you to Michael Scovetta from the OpenSSF Alpha-Omega project for
    reporting this vulnerability. Impacts: (CVE-2022-32222)

  - AES OCB mode for 32-bit x86 platforms using the AES-NI assembly optimised implementation will not encrypt
    the entirety of the data under some circumstances.  This could reveal sixteen bytes of data that was
    preexisting in the memory that wasn't written.  In the special case of in place encryption, sixteen
    bytes of the plaintext would be revealed. Since OpenSSL does not support OCB based cipher suites for TLS
    and DTLS, they are both unaffected. Impacts: (CVE-2022-2097)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://nodejs.org/en/blog/vulnerability/july-2022-security-releases/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Node.js version 14.20.0 / 16.16.0 / 18.5.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2097");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-32212");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/07");
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
  { 'min_version' : '14.0.0', 'fixed_version' : '14.20.0' },
  { 'min_version' : '16.0.0', 'fixed_version' : '16.16.0' },
  { 'min_version' : '18.0.0', 'fixed_version' : '18.5.0' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

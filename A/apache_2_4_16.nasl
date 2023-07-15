#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84959);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2015-0228",
    "CVE-2015-0253",
    "CVE-2015-3183",
    "CVE-2015-3185"
  );
  script_bugtraq_id(
    73041,
    75963,
    75964,
    75965
  );

  script_name(english:"Apache 2.4.x < 2.4.16 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache 2.4.x installed on the
remote host is prior to 2.4.16. It is, therefore, affected by the
following vulnerabilities :

  - A flaw exists in the lua_websocket_read() function in
    the 'mod_lua' module due to incorrect handling of
    WebSocket PING frames. A remote attacker can exploit
    this, by sending a crafted WebSocket PING frame after a
    Lua script has called the wsupgrade() function, to crash
    a child process, resulting in a denial of service
    condition. (CVE-2015-0228)

  - A NULL pointer dereference flaw exists in the
    read_request_line() function due to a failure to
    initialize the protocol structure member. A remote 
    attacker can exploit this flaw, on installations that
    enable the INCLUDES filter and has an ErrorDocument 400
    directive specifying a local URI, by sending a request
    that lacks a method, to cause a denial of service
    condition. (CVE-2015-0253)

  - A flaw exists in the chunked transfer coding
    implementation due to a failure to properly parse chunk
    headers. A remote attacker can exploit this to conduct
    HTTP request smuggling attacks. (CVE-2015-3183)

  - A flaw exists in the ap_some_auth_required() function
    due to a failure to consider that a Require directive
    may be associated with an authorization setting rather
    than an authentication setting. A remote attacker can
    exploit this, if a module that relies on the 2.2 API
    behavior exists, to bypass intended access restrictions.
    (CVE-2015-3185)

  - A flaw exists in the RC4 algorithm due to an initial
    double-byte bias in the keystream generation. An
    attacker can exploit this, via Bayesian analysis that
    combines an a priori plaintext distribution with
    keystream distribution statistics, to conduct a
    plaintext recovery of the ciphertext. Note that RC4
    cipher suites are prohibited per RFC 7465. This issue
    was fixed in Apache version 2.4.13; however, 2.4.13,
    2.4.14, and 2.4.15 were never publicly released.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.4.16");
  script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/security/vulnerabilities_24.html");
  # http://svn.apache.org/viewvc/httpd/httpd/tags/2.4.13/CHANGES?revision=1683584&view=markup
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ec9a07a");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc7465");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.16 or later. Alternatively, ensure that
the affected modules are not in use.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3183");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_http_version.nasl", "apache_http_server_nix_installed.nbin", "apache_httpd_win_installed.nbin");
  script_require_keys("installed_sw/Apache");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');


app_info = vcf::apache_http_server::combined_get_app_info(app:'Apache');

constraints = [
  { 'min_version' : '2.3.0', 'fixed_version' : '2.4.16' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

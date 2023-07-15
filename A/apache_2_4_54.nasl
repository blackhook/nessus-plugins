##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161948);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/19");

  script_cve_id(
    "CVE-2022-26377",
    "CVE-2022-28330",
    "CVE-2022-28614",
    "CVE-2022-28615",
    "CVE-2022-29404",
    "CVE-2022-30522",
    "CVE-2022-30556",
    "CVE-2022-31813"
  );
  script_xref(name:"IAVA", value:"2022-A-0230-S");

  script_name(english:"Apache 2.4.x < 2.4.54 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache httpd installed on the remote host is prior to 2.4.54. It is, therefore, affected by multiple
vulnerabilities as referenced in the 2.4.54 advisory.

  - Possible request smuggling in mod_proxy_ajp: Inconsistent Interpretation of HTTP Requests ('HTTP Request
    Smuggling') vulnerability in mod_proxy_ajp of Apache HTTP Server allows an attacker to smuggle requests to
    the AJP server it forwards requests to.  This issue affects Apache HTTP Server Apache HTTP Server 2.4
    version 2.4.53 and prior versions. Acknowledgements: Ricter Z @ 360 Noah Lab (CVE-2022-26377)

  - Read beyond bounds in mod_isapi: Apache HTTP Server 2.4.53 and earlier on Windows may read beyond bounds
    when configured to process requests with the mod_isapi module.  Acknowledgements: The Apache HTTP Server
    project would like to thank Ronald Crane (Zippenhop LLC) for reporting this issue (CVE-2022-28330)

  - Read beyond bounds via ap_rwrite(): The ap_rwrite() function in Apache HTTP Server 2.4.53 and earlier may
    read unintended memory if an attacker can cause the server to reflect very large input using ap_rwrite()
    or ap_rputs(), such as with mod_luas r:puts() function. Acknowledgements: The Apache HTTP Server project
    would like to thank Ronald Crane (Zippenhop LLC) for reporting this issue (CVE-2022-28614)

  - Read beyond bounds in ap_strcmp_match(): Apache HTTP Server 2.4.53 and earlier may crash or disclose
    information due to a read beyond bounds in ap_strcmp_match() when provided with an extremely large input
    buffer.  While no code distributed with the server can be coerced into such a call, third-party modules or
    lua scripts that use ap_strcmp_match() may hypothetically be affected. Acknowledgements: The Apache HTTP
    Server project would like to thank Ronald Crane (Zippenhop LLC) for reporting this issue (CVE-2022-28615)

  - Denial of service in mod_lua r:parsebody: In Apache HTTP Server 2.4.53 and earlier, a malicious request to a
    lua script that calls r:parsebody(0) may cause a denial of service due to no default limit on possible
    input size. Acknowledgements: The Apache HTTP Server project would like to thank Ronald Crane (Zippenhop
    LLC) for reporting this issue (CVE-2022-29404)

  - Denial of Service mod_sed: If Apache HTTP Server 2.4.53 is configured to do transformations with mod_sed in
    contexts where the input to mod_sed may be very large, mod_sed may make excessively large memory
    allocations and trigger an abort. Acknowledgements: This issue was found by Brian Moussalli from the JFrog
    Security Research team (CVE-2022-30522)

  - Information Disclosure in mod_lua with websockets: Apache HTTP Server 2.4.53 and earlier may return lengths
    to applications calling r:wsread() that point past the end of the storage allocated for the buffer.
    Acknowledgements: The Apache HTTP Server project would like to thank Ronald Crane (Zippenhop LLC) for
    reporting this issue (CVE-2022-30556)

  - X-Forwarded-For dropped by hop-by-hop mechanism in mod_proxy: Apache HTTP Server 2.4.53 and earlier may not
    send the X-Forwarded-* headers to the origin server based on client side Connection header hop-by-hop
    mechanism. This may be used to bypass IP based authentication on the origin server/application.
    Acknowledgements: The Apache HTTP Server project would like to thank Gaetan Ferry (Synacktiv) for
    reporting this issue (CVE-2022-31813)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://httpd.apache.org/security/vulnerabilities_24.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.4.54 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31813");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:httpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_http_version.nasl", "apache_http_server_nix_installed.nbin", "apache_httpd_win_installed.nbin");
  script_require_keys("installed_sw/Apache");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::apache_http_server::combined_get_app_info(app:'Apache');

var constraints = [
  { 'max_version' : '2.4.53', 'fixed_version' : '2.4.54' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

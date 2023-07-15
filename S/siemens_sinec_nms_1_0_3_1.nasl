#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175628);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/15");

  script_cve_id(
    "CVE-2022-32221",
    "CVE-2022-35252",
    "CVE-2022-35260",
    "CVE-2022-40674",
    "CVE-2022-42915",
    "CVE-2022-42916",
    "CVE-2022-43551",
    "CVE-2022-43552",
    "CVE-2022-43680"
  );
  script_xref(name:"ICSA", value:"23-131-05");

  script_name(english:"Siemens SINEC NMS < V1.0 SP2 Update 1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"Siemens SINEC NMS Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Siemens SINEC NMS installed on the remote host is prior to 1.0.3.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the SSA-892048 advisory.

  - When doing HTTP(S) transfers, libcurl might erroneously use the read callback (`CURLOPT_READFUNCTION`) to
    ask for data to send, even when the `CURLOPT_POSTFIELDS` option has been set, if the same handle
    previously was used to issue a `PUT` request which used that callback. This flaw may surprise the
    application and cause it to misbehave and either send off the wrong data or use memory after free or
    similar in the subsequent `POST` request. The problem exists in the logic for a reused handle when it is
    changed from a PUT to a POST. (CVE-2022-32221)

  - When curl is used to retrieve and parse cookies from a HTTP(S) server, itaccepts cookies using control
    codes that when later are sent back to a HTTPserver might make the server return 400 responses.
    Effectively allowing a 'sister site to deny service to all siblings. (CVE-2022-35252)

  - curl can be told to parse a `.netrc` file for credentials. If that file endsin a line with 4095
    consecutive non-white space letters and no newline, curlwould first read past the end of the stack-based
    buffer, and if the readworks, write a zero byte beyond its boundary.This will in most cases cause a
    segfault or similar, but circumstances might also cause different outcomes.If a malicious user can provide
    a custom netrc file to an application or otherwise affect its contents, this flaw could be used as denial-
    of-service. (CVE-2022-35260)

  - libexpat before 2.4.9 has a use-after-free in the doContent function in xmlparse.c. (CVE-2022-40674)

  - A use after free vulnerability exists in curl <7.87.0. Curl can be asked to *tunnel* virtually all
    protocols it supports through an HTTP proxy. HTTP proxies can (and often do) deny such tunnel operations.
    When getting denied to tunnel the specific protocols SMB or TELNET, curl would use a heap-allocated struct
    after it had been freed, in its transfer shutdown code path. (CVE-2022-43552)

  - In libexpat through 2.4.9, there is a use-after free caused by overeager destruction of a shared DTD in
    XML_ExternalEntityParserCreate in out-of-memory situations. (CVE-2022-43680)

  - curl before 7.86.0 has a double free. If curl is told to use an HTTP proxy for a transfer with a non-
    HTTP(S) URL, it sets up the connection to the remote server by issuing a CONNECT request to the proxy, and
    then tunnels the rest of the protocol through. An HTTP proxy might refuse this request (HTTP proxies often
    only allow outgoing connections to specific port numbers, like 443 for HTTPS) and instead return a non-200
    status code to the client. Due to flaws in the error/cleanup handling, this could trigger a double free in
    curl if one of the following schemes were used in the URL for the transfer: dict, gopher, gophers, ldap,
    ldaps, rtmp, rtmps, or telnet. The earliest affected version is 7.77.0. (CVE-2022-42915)

  - In curl before 7.86.0, the HSTS check could be bypassed to trick it into staying with HTTP. Using its HSTS
    support, curl can be instructed to use HTTPS directly (instead of using an insecure cleartext HTTP step)
    even when HTTP is provided in the URL. This mechanism could be bypassed if the host name in the given URL
    uses IDN characters that get replaced with ASCII counterparts as part of the IDN conversion, e.g., using
    the character UTF-8 U+3002 (IDEOGRAPHIC FULL STOP) instead of the common ASCII full stop of U+002E (.).
    The earliest affected version is 7.77.0 2021-05-26. (CVE-2022-42916)

  - A vulnerability exists in curl <7.87.0 HSTS check that could be bypassed to trick it to keep using HTTP.
    Using its HSTS support, curl can be instructed to use HTTPS instead of using an insecure clear-text HTTP
    step even when HTTP is provided in the URL. However, the HSTS mechanism could be bypassed if the host name
    in the given URL first uses IDN characters that get replaced to ASCII counterparts as part of the IDN
    conversion. Like using the character UTF-8 U+3002 (IDEOGRAPHIC FULL STOP) instead of the common ASCII full
    stop (U+002E) `.`. Then in a subsequent request, it does not detect the HSTS state and makes a clear text
    transfer. Because it would store the info IDN encoded but look for it IDN decoded. (CVE-2022-43551)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cisa.gov/news-events/ics-advisories/icsa-23-131-05");
  # https://cert-portal.siemens.com/productcert/html/ssa-892048.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a85d6fc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Siemens SINEC NMS Server version 11 Update 3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42915");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:siemens:sinec_nms");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("siemens_sinec_nms_win_installed.nbin");
  script_require_keys("installed_sw/SINEC NMS");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'SINEC NMS');
var constraints = [{'fixed_version': '1.0.3.1', 'fixed_display': 'V1.0 SP3 Update 1'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);

#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170445);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/18");

  script_cve_id(
    "CVE-2022-32221",
    "CVE-2022-35260",
    "CVE-2022-3705",
    "CVE-2022-42915",
    "CVE-2022-42916",
    "CVE-2023-23493",
    "CVE-2023-23496",
    "CVE-2023-23497",
    "CVE-2023-23498",
    "CVE-2023-23499",
    "CVE-2023-23500",
    "CVE-2023-23501",
    "CVE-2023-23502",
    "CVE-2023-23503",
    "CVE-2023-23504",
    "CVE-2023-23505",
    "CVE-2023-23506",
    "CVE-2023-23507",
    "CVE-2023-23508",
    "CVE-2023-23510",
    "CVE-2023-23511",
    "CVE-2023-23512",
    "CVE-2023-23513",
    "CVE-2023-23517",
    "CVE-2023-23518",
    "CVE-2023-23519"
  );
  script_xref(name:"APPLE-SA", value:"HT213605");
  script_xref(name:"IAVA", value:"2023-A-0054-S");
  script_xref(name:"IAVA", value:"2023-A-0162-S");
  script_xref(name:"IAVB", value:"2023-B-0016-S");

  script_name(english:"macOS 13.x < 13.2 Multiple Vulnerabilities (HT213605)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 13.x prior to 13.2. It is, therefore, affected by
multiple vulnerabilities:

  - When doing HTTP(S) transfers, libcurl might erroneously use the read callback (`CURLOPT_READFUNCTION`) to
    ask for data to send, even when the `CURLOPT_POSTFIELDS` option has been set, if the same handle
    previously was used to issue a `PUT` request which used that callback. This flaw may surprise the
    application and cause it to misbehave and either send off the wrong data or use memory after free or
    similar in the subsequent `POST` request. The problem exists in the logic for a reused handle when it is
    changed from a PUT to a POST. (CVE-2022-32221)

  - curl can be told to parse a `.netrc` file for credentials. If that file endsin a line with 4095
    consecutive non-white space letters and no newline, curlwould first read past the end of the stack-based
    buffer, and if the readworks, write a zero byte beyond its boundary.This will in most cases cause a
    segfault or similar, but circumstances might also cause different outcomes.If a malicious user can provide
    a custom netrc file to an application or otherwise affect its contents, this flaw could be used as denial-
    of-service. (CVE-2022-35260)

  - A vulnerability was found in vim and classified as problematic. Affected by this issue is the function
    qf_update_buffer of the file quickfix.c of the component autocmd Handler. The manipulation leads to use
    after free. The attack may be launched remotely. Upgrading to version 9.0.0805 is able to address this
    issue. The name of the patch is d0fab10ed2a86698937e3c3fed2f10bd9bb5e731. It is recommended to upgrade the
    affected component. The identifier of this vulnerability is VDB-212324. (CVE-2022-3705)

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

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213605");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 13.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42915");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  { 'fixed_version' : '13.2.0', 'min_version' : '13.0', 'fixed_display' : 'macOS Ventura 13.2' }
];

vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

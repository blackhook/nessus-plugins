#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173444);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id(
    "CVE-2022-43551",
    "CVE-2022-43552",
    "CVE-2023-0049",
    "CVE-2023-0051",
    "CVE-2023-0054",
    "CVE-2023-0288",
    "CVE-2023-0433",
    "CVE-2023-0512",
    "CVE-2023-23514",
    "CVE-2023-23523",
    "CVE-2023-23525",
    "CVE-2023-23526",
    "CVE-2023-23527",
    "CVE-2023-23532",
    "CVE-2023-23533",
    "CVE-2023-23534",
    "CVE-2023-23535",
    "CVE-2023-23537",
    "CVE-2023-23538",
    "CVE-2023-23542",
    "CVE-2023-23543",
    "CVE-2023-27928",
    "CVE-2023-27929",
    "CVE-2023-27931",
    "CVE-2023-27932",
    "CVE-2023-27933",
    "CVE-2023-27934",
    "CVE-2023-27935",
    "CVE-2023-27936",
    "CVE-2023-27937",
    "CVE-2023-27941",
    "CVE-2023-27942",
    "CVE-2023-27943",
    "CVE-2023-27944",
    "CVE-2023-27946",
    "CVE-2023-27949",
    "CVE-2023-27951",
    "CVE-2023-27952",
    "CVE-2023-27953",
    "CVE-2023-27954",
    "CVE-2023-27955",
    "CVE-2023-27956",
    "CVE-2023-27957",
    "CVE-2023-27958",
    "CVE-2023-27961",
    "CVE-2023-27962",
    "CVE-2023-27963",
    "CVE-2023-27965",
    "CVE-2023-27968",
    "CVE-2023-27969",
    "CVE-2023-28178",
    "CVE-2023-28180",
    "CVE-2023-28181",
    "CVE-2023-28182",
    "CVE-2023-28190",
    "CVE-2023-28192",
    "CVE-2023-28200"
  );
  script_xref(name:"APPLE-SA", value:"HT213670");
  script_xref(name:"IAVA", value:"2023-A-0162-S");

  script_name(english:"macOS 13.x < 13.3 Multiple Vulnerabilities (HT213670)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 13.x prior to 13.3. It is, therefore, affected by
multiple vulnerabilities:

  - A vulnerability exists in curl <7.87.0 HSTS check that could be bypassed to trick it to keep using HTTP.
    Using its HSTS support, curl can be instructed to use HTTPS instead of using an insecure clear-text HTTP
    step even when HTTP is provided in the URL. However, the HSTS mechanism could be bypassed if the host name
    in the given URL first uses IDN characters that get replaced to ASCII counterparts as part of the IDN
    conversion. Like using the character UTF-8 U+3002 (IDEOGRAPHIC FULL STOP) instead of the common ASCII full
    stop (U+002E) `.`. Then in a subsequent request, it does not detect the HSTS state and makes a clear text
    transfer. Because it would store the info IDN encoded but look for it IDN decoded. (CVE-2022-43551)

  - A use after free vulnerability exists in curl <7.87.0. Curl can be asked to *tunnel* virtually all
    protocols it supports through an HTTP proxy. HTTP proxies can (and often do) deny such tunnel operations.
    When getting denied to tunnel the specific protocols SMB or TELNET, curl would use a heap-allocated struct
    after it had been freed, in its transfer shutdown code path. (CVE-2022-43552)

  - A use after free issue was addressed with improved memory management. This issue is fixed in macOS Ventura
    13.2.1, iOS 16.3.1 and iPadOS 16.3.1. An app may be able to execute arbitrary code with kernel
    privileges.. (CVE-2023-23514)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.1143. (CVE-2023-0049)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1144. (CVE-2023-0051)

  - Out-of-bounds Write in GitHub repository vim/vim prior to 9.0.1145. (CVE-2023-0054)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1189. (CVE-2023-0288)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.1225. (CVE-2023-0433)

  - Divide By Zero in GitHub repository vim/vim prior to 9.0.1247. (CVE-2023-0512)

  - A buffer overflow issue was addressed with improved memory handling. (CVE-2023-27957, CVE-2023-27968)

  - This issue was addressed with improved checks. (CVE-2023-23525, CVE-2023-23532, CVE-2023-27943)

  - The issue was addressed with improved checks. (CVE-2023-23527, CVE-2023-23534, CVE-2023-27942,
    CVE-2023-27951, CVE-2023-27955)

  - This issue was addressed by removing the vulnerable code. (CVE-2023-27931)

  - Multiple validation issues were addressed with improved input sanitization. (CVE-2023-27961)

  - The issue was addressed with additional restrictions on the observability of app states. (CVE-2023-23543)

  - An out-of-bounds write issue was addressed with improved input validation. (CVE-2023-27936)

  - The issue was addressed with improved memory handling. (CVE-2023-23535, CVE-2023-27933, CVE-2023-27953,
    CVE-2023-27956, CVE-2023-27958, CVE-2023-28181)

  - A memory initialization issue was addressed. (CVE-2023-27934)

  - A denial-of-service issue was addressed with improved memory handling. (CVE-2023-28180)

  - The issue was addressed with improved bounds checks. (CVE-2023-27935)

  - A memory corruption issue was addressed with improved state management. (CVE-2023-27965)

  - A privacy issue was addressed by moving sensitive data to a more secure location. (CVE-2023-28190)

  - A privacy issue was addressed with improved private data redaction for log entries. (CVE-2023-23537,
    CVE-2023-23542, CVE-2023-27928)

  - An integer overflow was addressed with improved input validation. (CVE-2023-27937)

  - This was addressed with additional checks by Gatekeeper on files downloaded from an iCloud shared-by-me
    folder. (CVE-2023-23526)

  - An out-of-bounds read was addressed with improved input validation. (CVE-2023-27929, CVE-2023-27949)

  - An out-of-bounds read was addressed with improved bounds checking. (CVE-2023-27946)

  - A use after free issue was addressed with improved memory management. (CVE-2023-27969)

  - An out-of-bounds read issue existed that led to the disclosure of kernel memory. This was addressed with
    improved input validation. (CVE-2023-27941)

  - A validation issue was addressed with improved input sanitization. (CVE-2023-28200)

  - The issue was addressed with improved authentication. (CVE-2023-28182)

  - A logic issue was addressed with improved checks. (CVE-2023-23533, CVE-2023-23538, CVE-2023-27962)

  - A logic issue was addressed with improved restrictions. (CVE-2023-23523)

  - A race condition was addressed with improved locking. (CVE-2023-27952)

  - A logic issue was addressed with improved validation. (CVE-2023-28178)

  - The issue was addressed with additional permissions checks. (CVE-2023-27963)

  - This issue was addressed with improved state management. (CVE-2023-27932)

  - The issue was addressed by removing origin information. (CVE-2023-27954)

  - This issue was addressed with a new entitlement. (CVE-2023-27944)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213670");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 13.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23526");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/27");

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
  { 'fixed_version' : '13.3.0', 'min_version' : '13.0', 'fixed_display' : 'macOS Ventura 13.3' }
];

vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121309);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/31 15:18:51");

  script_cve_id(
    "CVE-2018-12086",
    "CVE-2018-12585",
    "CVE-2018-18225",
    "CVE-2018-18226",
    "CVE-2018-18227"
  );
  script_bugtraq_id(105538, 105583);

  script_name(english:"Wireshark 2.4.x < 2.4.10 / 2.6.x < 2.6.4 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS / Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote macOS / Mac OS X
host is 2.4.x prior to 2.4.10 / 2.6.x prior to 2.6.4. It is,
therefore, affected by multiple vulnerabilities.

  - A buffer overflow condition exists in OPC UA applications due to
    failure to handle exceptional conditions. An unauthenticated
    remote attacker can exploit this via carefully structured requests
    to cause a denial of service condition or the execution of
    arbitrary code. (CVE-2018-12086)

  - A stack-based buffer overflow condition exists in Liblouis 3.6.0
    in the function parseChars in compileTranslationTable.c, a
    different vulnerability than CVE-2018-11440 due to failure to
    handle exceptional conditions. An unauthenticated remote attacker
    can exploit this to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2018-12585)

  - Multiple denial of service vulnerabilities exist in the following
    protocol dissectors: CoAP, IHS Discovery, the MS-WSP due to
    improper handling of exceptional conditions. An unauthenticated
    remote attacker can exploit this to cause Wireshark to crash by
    injecting a malformed packet onto the wire, or by convincing a
    user to read a malformed packet trace file.
    (CVE-2018-18225, CVE-2018-18226, CVE-2018-18227)");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.6.4.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-47.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-48.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-49.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-50.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.4.10 / 2.6.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12585");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_wireshark_installed.nbin");
  script_require_keys("installed_sw/Wireshark", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("Host/MacOSX/Version");

app_info = vcf::get_app_info(app:"Wireshark");

constraints = [
  { "min_version" : "2.6.0", "fixed_version" : "2.6.4" },
  { "min_version" : "2.4.0", "fixed_version" : "2.4.10" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

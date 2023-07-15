#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121307);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/31 15:18:51");

  script_cve_id(
    "CVE-2018-14339",
    "CVE-2018-14340",
    "CVE-2018-14341",
    "CVE-2018-14342",
    "CVE-2018-14343",
    "CVE-2018-14344",
    "CVE-2018-14367",
    "CVE-2018-14368",
    "CVE-2018-14369",
    "CVE-2018-14370"
  );
  script_bugtraq_id(104847);

  script_name(english:"Wireshark 2.2.x < 2.2.16 / 2.4.x < 2.4.8 / 2.6.x < 2.6.2 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS / Mac OS X host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote macOS / Mac OS X host
is 2.2.x prior to 2.2.16 / 2.4.x prior to 2.4.8 / 2.6.x prior to 2.6.2.
It is, therefore, affected by multiple denial of service 
vulnerabilities in the following protocol dissectors:

  - MMSE

  - zlib decompression

  - DICOM

  - BGP

  - ASN.1 BER

  - ISMP

  - CoAP

  - Bazaar

  - HTTP2

  - IEEE 802.11
                                                                      
An attacker could cause Wireshark to crash by injecting a malformed   
packet onto the wire, or by convincing a user to read a malformed     
packet trace file.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.6.2.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-34.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-35.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-36.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-37.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-38.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-39.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-40.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-41.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2018-42.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.2.16 / 2.4.8 /2.6.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14341");

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
  { "min_version" : "2.6.0", "fixed_version" : "2.6.2" },
  { "min_version" : "2.4.0", "fixed_version" : "2.4.8" },
  { "min_version" : "2.2.0", "fixed_version" : "2.2.16" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

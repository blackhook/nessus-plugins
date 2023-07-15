#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69105);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2013-4083",
    "CVE-2013-4920",
    "CVE-2013-4921",
    "CVE-2013-4922",
    "CVE-2013-4923",
    "CVE-2013-4924",
    "CVE-2013-4925",
    "CVE-2013-4926",
    "CVE-2013-4927",
    "CVE-2013-4928",
    "CVE-2013-4929",
    "CVE-2013-4930",
    "CVE-2013-4931",
    "CVE-2013-4932",
    "CVE-2013-4933",
    "CVE-2013-4934",
    "CVE-2013-4935",
    "CVE-2013-4936"
  );
  script_bugtraq_id(60504, 61471);

  script_name(english:"Wireshark 1.10.x < 1.10.1 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark 1.10 is earlier than 1.10.1.  It is,
therefore, affected by denial of service vulnerabilities in the
following dissectors :

  - ASN.1 PER (Bug #8722)
  - Bluetooth OBEX (Bug #8875)
  - Bluetooth SDP (Bug #8831)
  - DCOM ISystemActivator (Bug #8828)
  - DCP ETSI (Bug #8717)
  - DIS (Bug #8911)
  - DVB-CI (Bug #8916)
  - GSM A Common (Bug #8940)
  - GSM RR (Bug #8923)
  - Netmon file parser (Bug #8742)
  - P1 (Bug #8826)
  - PROFINET Real-Time (Bug #8904)
  - Radiotap (Bug #8830)");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-41.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-42.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-43.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-44.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-45.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-46.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-47.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-48.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-49.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-50.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-51.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-52.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-53.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.10.1.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 1.10.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4929");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '1.10.0', 'max_version' : '1.10.0', 'fixed_version' : '1.10.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

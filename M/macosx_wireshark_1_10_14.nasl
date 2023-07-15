#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176374);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id("CVE-2015-3811", "CVE-2015-3812", "CVE-2015-3814");
  script_xref(name:"IAVB", value:"2015-B-0067-S");

  script_name(english:"Wireshark 1.10.x < 1.10.14 Multiple Vulnerabilities (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS / Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote macOS / Mac OS X host is prior to 1.10.14. It is, therefore, affected
by multiple vulnerabilities as referenced in the wireshark-1.10.14 advisory.

  - epan/dissectors/packet-wcp.c in the WCP dissector in Wireshark 1.10.x before 1.10.14 and 1.12.x before
    1.12.5 improperly refers to previously processed bytes, which allows remote attackers to cause a denial of
    service (application crash) via a crafted packet, a different vulnerability than CVE-2015-2188.
    (CVE-2015-3811)

  - Multiple memory leaks in the x11_init_protocol function in epan/dissectors/packet-x11.c in the X11
    dissector in Wireshark 1.10.x before 1.10.14 and 1.12.x before 1.12.5 allow remote attackers to cause a
    denial of service (memory consumption) via a crafted packet. (CVE-2015-3812)

  - The (1) dissect_tfs_request and (2) dissect_tfs_response functions in epan/dissectors/packet-ieee80211.c
    in the IEEE 802.11 dissector in Wireshark 1.10.x before 1.10.14 and 1.12.x before 1.12.5 interpret a zero
    value as a length rather than an error condition, which allows remote attackers to cause a denial of
    service (infinite loop) via a crafted packet. (CVE-2015-3814)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.10.14.html");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/10978");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-14");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/11088");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-15");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/11110");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-17");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 1.10.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3812");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-3814");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_wireshark_installed.nbin");
  script_require_keys("installed_sw/Wireshark", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Wireshark');

var constraints = [
  { 'min_version' : '1.10.0', 'max_version' : '1.10.13', 'fixed_version' : '1.10.14' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

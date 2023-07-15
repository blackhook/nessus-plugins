#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(103981);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id("CVE-2017-15191");
  script_bugtraq_id(101227);

  script_name(english:"Wireshark 2.0.x < 2.0.16 DMP dissector DoS (MacOS)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS / Mac OS X host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote MacOS(X) host is 
2.0.x prior to 2.0.16. It is, therefore, affected by a denial 
of service vulnerability in the DMP dissector. An unauthenticated, 
remote attacker can exploit this by injecting a malformed packet 
onto the wire or by convincing someone to read a malformed packet 
trace file.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.0.16.html");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/14068");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-44");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.0.16 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15191");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_wireshark_installed.nbin");
  script_require_keys("installed_sw/Wireshark", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Wireshark');

var constraints = [
  { 'min_version' : '2.0.0', 'max_version' : '2.0.15', 'fixed_version' : '2.0.16' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

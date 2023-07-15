#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66543);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id("CVE-2013-3556", "CVE-2013-3557");
  script_bugtraq_id(59997, 60021);

  script_name(english:"Wireshark 1.6.x < 1.6.15 ASN.1 BER Dissector Malformed Packet Handling DoS");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark 1.6 is earlier than 1.6.15.  It is,
therefore, affected by a denial of service vulnerability in the ASN.1
BER dissector when handling malformed packets.  (Bug 8599)");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2013-25.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.6.15.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 1.6.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-3557");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/22");

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
  { 'min_version' : '1.6.0', 'max_version' : '1.6.14', 'fixed_version' : '1.6.15' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

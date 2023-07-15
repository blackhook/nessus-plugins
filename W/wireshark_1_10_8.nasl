#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76150);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id("CVE-2014-4020");
  script_bugtraq_id(68044);

  script_name(english:"Wireshark 1.10.x < 1.10.8 Metadissector DoS");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark 1.10.x is a version prior to
1.10.8. It is, therefore, affected by a denial of service
vulnerability. A flaw exists with the Metadissector dissector when
handling a malformed packet that could allow a remote attacker to
crash Wireshark.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-07.html");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=9999");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=10030");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.10.8.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.10.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2023 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '1.10.0', 'max_version' : '1.10.7', 'fixed_version' : '1.10.8' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

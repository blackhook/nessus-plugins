#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62477);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id("CVE-2012-3548");
  script_bugtraq_id(55284);

  script_name(english:"Wireshark 1.6.x < 1.6.11 DRDA DoS");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark 1.6 is earlier than 1.6.11.  It thus
is affected by a denial of service vulnerability.  A malformed packet
can cause the 'DRDA' dissector to enter an infinite loop thereby
consuming excessive CPU resources.");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-28.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.6.11.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.6.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2023 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '1.6.0', 'max_version' : '1.6.10', 'fixed_version' : '1.6.11' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55411);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id("CVE-2011-1956");
  script_bugtraq_id(48389);
  script_xref(name:"Secunia", value:"44449");

  script_name(english:"Wireshark 1.4.5 Denial of Service");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark, version 1.4.5, is affected by a
denial of service vulnerability.  An attacker can exploit this
vulnerability by crafting a malicious TCP packet and sending it on a
network segment that Wireshark is monitoring, causing the application
to crash.");

  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5837");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.4.6.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.4.6 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/23");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2023 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '1.4.5', 'max_version' : '1.4.5', 'fixed_version' : '1.4.6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

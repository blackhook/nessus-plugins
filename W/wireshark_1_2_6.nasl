#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44338);
  script_version("1.14");

  script_cve_id("CVE-2010-0304");
  script_bugtraq_id(37985);

  script_name(english:"Wireshark / Ethereal Dissector LWRES Multiple Buffer Overflows");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis",value:
"The remote host has an application that is affected by several buffer
overflows."
  );
  script_set_attribute(attribute:"description",value:
"The installed version of Wireshark or Ethereal is potentially
vulnerable to attack by handling data associated with the LWRES
dissector. 

These vulnerabilities can result in a denial of service, or possibly
arbitrary code execution.  A remote attacker can exploit these issues
by tricking a user into opening a maliciously crafted capture file. 
Additionally, if Wireshark is running in promiscuous mode, one of
these issues can be exploited remotely."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/security/wnpa-sec-2010-02.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Wireshark version 1.0.11 / 1.2.6 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Wireshark LWRES Dissector getaddrsbyname_request Buffer Overflow (loop)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');
  script_cwe_id(119);
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2010/01/27"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/01/27"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2010/01/29"
  );
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2023 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");

exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '0.9.15', 'max_version' : '1.0.10', 'fixed_version' : '1.10.11' },
  { 'min_version' : '1.2.0', 'max_version' : '1.2.5', 'fixed_version' : '1.2.6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

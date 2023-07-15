#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51458);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id("CVE-2010-4538", "CVE-2011-0444", "CVE-2011-0445");
  script_bugtraq_id(45634, 45775);
  script_xref(name:"Secunia", value:"42767");

  script_name(english:"Wireshark < 1.2.14 / 1.4.3 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark is 1.2.x less than 1.2.14 or 1.4.x
less than 1.4.3.  Such versions are affected by the following
vulnerabilities :
  
  - An error exists in the MAC-LTE dissector that allows a
    series of malformed packets to cause a buffer overflow.
    (5530)

  - An error exists in the ENTTEC dissector that allows a
    series of malformed packets to cause a buffer overflow.
    (5539)

  - An error exists in the ASN.1 BER dissector that allows
    a series of malformed packets to make Wireshark exit
    prematurely. (5537)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2011-01.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2011-02.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.2.14.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.4.3.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.2.14 / 1.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/12");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
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
  { 'min_version' : '1.4.0', 'max_version' : '1.4.2', 'fixed_version' : '1.4.3' },
  { 'min_version' : '1.2.0', 'max_version' : '1.2.13', 'fixed_version' : '1.2.14' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

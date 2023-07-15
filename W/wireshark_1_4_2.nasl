#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50678);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id("CVE-2010-4300", "CVE-2010-4301");
  script_bugtraq_id(44986, 44987);
  script_xref(name:"EDB-ID", value:"15973");
  script_xref(name:"Secunia", value:"42290");

  script_name(english:"Wireshark < 1.2.13 / 1.4.2 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark is 1.2.x less than 1.2.13 or 1.4.x
less than 1.4.2.  Such versions are affected by the following
vulnerabilities:

  - An error exists in the LDSS dissector that allows 
    a series of malformed packets to cause a buffer
    overflow. (5318)

  - An error exists in the ZigBee ZCL dissector that allows
    a series of malformed packets to cause the dissector to
    enter an infinite loop. (5303)"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.wireshark.org/security/wnpa-sec-2010-13.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://www.wireshark.org/security/wnpa-sec-2010-14.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.wireshark.org/docs/relnotes/wireshark-1.2.13.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.wireshark.org/docs/relnotes/wireshark-1.4.2.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Wireshark version 1.2.13 / 1.4.2 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/22");
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
  { 'min_version' : '1.4.0', 'max_version' : '1.4.1', 'fixed_version' : '1.4.2' },
  { 'min_version' : '1.2.0', 'max_version' : '1.2.12', 'fixed_version' : '1.2.13' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

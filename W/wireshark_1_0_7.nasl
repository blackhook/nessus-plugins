#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(36127);
  script_version("1.19");

  script_cve_id(
    "CVE-2009-1210",
    "CVE-2009-1267",
    "CVE-2009-1268",
    "CVE-2009-1269"
  );
  script_bugtraq_id(34291,34457);
  script_xref(name:"EDB-ID", value:"8308");
  script_xref(name:"Secunia", value:"34542");

  script_name(english:"Wireshark / Ethereal 0.99.2 to 1.0.6 Multiple Vulnerabilities");
  script_summary(english:"Checks Wireshark / Ethereal version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark or Ethereal is affected by multiple
issues :

  - The PROFINET dissector is affected by a format string
    vulnerability which an attacker could exploit to execute
    arbitrary code. (Bug 3372)

  - Wireshark could crash while reading a malformed LDAP
    capture file. (Bug 3262)

  - Wireshark could crash while reading a malformed Check
    Point High-Availability Protocol capture file. 
    (Bug 3269)

  - Wireshark could crash while reading a Tektronix .rf5
    capture file. (Bug 3366)" );
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3382" );
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3262" );
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3269" );
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3366" );
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2009-02.html" );
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.0.7.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark 1.0.7 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 134);

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2023 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");
  
  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '0.99.2', 'max_version' : '1.0.6', 'fixed_version' : '1.0.7' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

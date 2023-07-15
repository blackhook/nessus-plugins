#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35629);
  script_version("1.15");

  script_cve_id("CVE-2009-0599", "CVE-2009-0600");
  script_bugtraq_id(33690);
  script_xref(name:"Secunia", value:"33872");

  script_name(english:"Wireshark / Ethereal 0.99.6 to 1.0.5 Multiple Denial of Service Vulnerabilities");
  script_summary(english:"Checks Wireshark / Ethereal version"); 

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is susceptible to multiple
denial of service attacks." );
 script_set_attribute(attribute:"description", value:
"The installed version of Wireshark or Ethereal is affected by multiple
denial of service issues :

  - Wireshark could crash while reading a malformed NetScreen
    snoop file. (Bug 3151)

  - Wireshark could crash while reading a Tektronix K12 
    text capture file. (Bug 1937)" );
 script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3151" );
 script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=1937" );
 script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2009-01.html" );
 script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/news/20090206.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark 1.0.6 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/02/10");
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
  { 'min_version' : '0.99.6', 'max_version' : '1.0.5', 'fixed_version' : '1.0.6' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);


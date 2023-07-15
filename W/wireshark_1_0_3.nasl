#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34113);
  script_version("1.13");

  script_bugtraq_id(31009);

  script_name(english:"Wireshark / Ethereal < 1.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks Wireshark / Ethereal version"); 

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The installed version of Wireshark or Ethereal is affected by multiple
issues :

  - The NCP dissector is affected by multiple buffer
    overflow flaws, and in certain cases may enter a 
    infinite loop (Bug 2675).

  - While uncompressing zlib-compressed packet data, 
    Wireshark could crash (Bug 2649).

  - While reading a Tektronix .rf5 file, Wireshark could 
    crash." );
 script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2008-05.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark 1.0.3 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/09");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");
  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);
var constraints = [
  {
    'min_version' : '0.9.7', 'max_version' : '1.0.2', 'fixed_version' : '1.0.3'
  }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);


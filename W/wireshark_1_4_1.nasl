#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49978);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id("CVE-2010-3445");
  script_bugtraq_id(43197);
  script_xref(name:"Secunia", value:"41535");

  script_name(english:"Wireshark < 1.2.12 / 1.4.1 ASN.1 BER Dissector Denial of Service");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is vulnerable to
a denial of service attack."
  );
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark is 1.2.x less than 1.2.12 or 1.4.x
less than 1.4.1.  Such versions are affected by a denial of service
vulnerability.  The ASN.1 BER dissector contains a flaw that can allow
a stack overflow that in turn can cause the application to crash."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://seclists.org/bugtraq/2010/Sep/87"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://www.wireshark.org/security/wnpa-sec-2010-11.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.wireshark.org/security/wnpa-sec-2010-12.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Wireshark version 1.2.12 / 1.4.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/14");
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
  { 'min_version' : '1.2.0', 'max_version' : '1.2.11', 'fixed_version' : '1.2.12' },
  { 'min_version' : '1.4.0', 'max_version' : '1.4.0', 'fixed_version' : '1.4.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56689);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id("CVE-2011-4101", "CVE-2011-4102");
  script_bugtraq_id(50481, 50486);

  script_name(english:"Wireshark 1.4.x < 1.4.10 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark is 1.4.x before 1.4.10.  This
version is affected by the following vulnerabilities :

  - An error exists in the Infiniband dissector that can
    allow a NULL pointer to be dereferenced when processing
    certain malformed packets. (CVE-2011-4101)

  - A buffer overflow exists in the ERF file reader and can
    be triggered when processing certain malformed packets.
    (CVE-2011-4102)");

  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2011-18.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2011-19.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.4.10.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.4.10 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/02");

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
  { 'min_version' : '1.4.0', 'max_version' : '1.4.9', 'fixed_version' : '1.4.10' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

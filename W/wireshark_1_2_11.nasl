#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(48943);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id("CVE-2010-3133");
  script_bugtraq_id(42630);
  script_xref(name:"EDB-ID", value:"14721");

  script_name(english:"Wireshark / Ethereal < 1.2.11 / 1.0.16 Path Subversion Arbitrary DLL Injection Code Execution");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis",value:
"The remote Windows host contains an application that allows arbitrary
code execution."
  );
  script_set_attribute(attribute:"description",value:
"The installed version of Wireshark or Ethereal is 1.2.0 - 1.2.10 or
0.8.4 - 1.0.15.  Such versions are affected by the following
vulnerability :

  - The application uses a fixed path to look for specific
    files or libraries, such as for 'airpcap.dll', and this
    path includes directories that may not be trusted or
    under user control. If a malicious DLL with the same
    name as a required DLL is located in the application's
    current working directory, the malicious DLL will be
    loaded. (Bug 5133)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.microsoft.com/en-us/windows/desktop/Dlls/dynamic-link-library-security"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.acrossecurity.com/aspr/ASPR-2010-08-18-1-PUB.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blog.rapid7.com/?p=5325"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5133"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://www.wireshark.org/security/wnpa-sec-2010-09.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://www.wireshark.org/security/wnpa-sec-2010-10.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Wireshark version 1.2.11 / 1.0.16 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/31");
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
  { 'min_version' : '1.2.0', 'max_version' : '1.2.10', 'fixed_version' : '1.2.11' },
  { 'min_version' : '0.8.4', 'max_version' : '1.0.15', 'fixed_version' : '1.0.16' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

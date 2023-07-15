#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56164);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2011-3266",
    "CVE-2011-3360",
    "CVE-2011-3482",
    "CVE-2011-3483",
    "CVE-2011-3484"
  );
  script_bugtraq_id(
    49377,
    49521,
    49522,
    49524,
    49528
  );
  script_xref(name:"EDB-ID", value:"18125");

  script_name(english:"Wireshark 1.6.x < 1.6.2 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark is 1.6.x before 1.6.2.  This
version is affected by the following vulnerabilities :

  - An error exists in IKE dissector that can allow denial
    of service attacks when processing certain malformed
    packets. (CVE-2011-3266)

  - A buffer exception handling vulnerability exists that
    can allow denial of service attacks when processing
    certain malformed packets. (Issue #6135)

  - It may be possible to make Wireshark execute Lua scripts
    using a method similar to DLL hijacking. (Issue #6136)

  - An error exists in OpenSafety dissector that can allow
    denial of service attacks when processing certain
    malformed packets. (Issue #6138)

  - An error exists in CSN.1 dissector that can allow denial
    of service attacks when processing certain malformed
    packets. (Issue #6139)");

  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2011-12.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2011-13.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2011-14.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2011-15.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2011-16.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.6.2.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.6.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Wireshark console.lua Pre-Loading Script Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');
script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/12");

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
  { 'min_version' : '1.6.0', 'max_version' : '1.6.1', 'fixed_version' : '1.6.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62478);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2012-3548",
    "CVE-2012-5237",
    "CVE-2012-5238",
    "CVE-2012-5240"
  );
  script_bugtraq_id(55284, 55754);

  script_name(english:"Wireshark 1.8.x < 1.8.3 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark 1.8 is earlier than 1.8.3.  It thus
is affected by the following vulnerabilities :

  - A malformed packet can cause the 'DRDA' and 'HSRP'
    dissectors to enter an infinite loop, thereby consuming
    excessive CPU resources. (CVE-2012-3548, CVE-2012-5237)

  - A malformed packet can cause the 'PPP' dissector to
    crash the application. (CVE-2012-5238)

  - A malformed packet can trigger a buffer overflow in the
    'LDP' dissector, which results in an application crash.
    (CVE-2012-5240)");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-26.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-27.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-28.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-29.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.3.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 1.8.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5240");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '1.8.0', 'max_version' : '1.8.2', 'fixed_version' : '1.8.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77732);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2014-6423",
    "CVE-2014-6424",
    "CVE-2014-6425",
    "CVE-2014-6426",
    "CVE-2014-6427",
    "CVE-2014-6428",
    "CVE-2014-6429",
    "CVE-2014-6430",
    "CVE-2014-6431",
    "CVE-2014-6432"
  );
  script_bugtraq_id(
    69853,
    69857,
    69858,
    69859,
    69860,
    69861,
    69862,
    69863,
    69865,
    69866
  );

  script_name(english:"Wireshark 1.12.x < 1.12.1 Multiple DoS Vulnerabilities");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark is version 1.12.x prior to 1.12.1.
It is, therefore, affected by the following vulnerabilities :

  - Errors exist in the following dissectors that can cause
    the application to crash :

    - CUPS (CVE-2014-6425)
    - HIP (CVE-2014-6426)
    - MEGACO (CVE-2014-6423)
    - Netflow (CVE-2014-6424)
    - RTSP (CVE-2014-6427)
    - SES (CVE-2014-6428)

  - Unspecified errors exist related to file parsing that
    can cause the parser to crash. (CVE-2014-6429,
    CVE-2014-6430, CVE-2014-6431, CVE-2014-6432)

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-13.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-14.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-15.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-16.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-17.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-18.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-19.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.1.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 1.12.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-6432");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wireshark_installed.nasl");
  script_require_ports("installed_sw/Wireshark", "installed_sw/Ethereal");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '1.12.0', 'max_version' : '1.12.0', 'fixed_version' : '1.12.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);


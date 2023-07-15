#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60116);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id("CVE-2012-4048", "CVE-2012-4049");
  script_bugtraq_id(54649);

  script_name(english:"Wireshark 1.4.x < 1.4.14 Multiple Denial of Service Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark is 1.4.x before 1.4.14.  This
version is affected by the following vulnerabilities :

  - An error exists in the 'PPP' dissector that can cause
    the application to crash when reading a malformed
    packet from either the wire or from a capture file.
    (CVE-2012-4048)

  - An error exists in the 'NFS' dissector that can cause
    the application to consume excessive CPU resources when
    reading a malformed packet from either the wire or from
    a capture file. (CVE-2012-4049)");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=680056");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7436");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-11.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/security/wnpa-sec-2012-12.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 1.4.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4048");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/25");

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
  { 'min_version' : '1.4.0', 'max_version' : '1.4.13', 'fixed_version' : '1.4.14' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

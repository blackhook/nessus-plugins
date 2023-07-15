#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72942);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2014-2281",
    "CVE-2014-2282",
    "CVE-2014-2283",
    "CVE-2014-2299"
  );
  script_bugtraq_id(
    66066,
    66068,
    66070,
    66072
  );

  script_name(english:"Wireshark 1.10.x < 1.10.6 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark 1.10.x is a version prior to 1.10.6. 
It is, therefore, affected by denial of service vulnerabilities in the
following dissectors :

  - NFS dissector (CVE-2014-2281)
  - M3UA dissector (CVE-2014-2282)
  - RLC dissector (CVE-2014-2283)

Additionally, a flaw exists in the 'mpeg_read()' function in the MPEG
file parser, 'wiretap/mpeg.c', where input is not properly sanitized
when handling oversized records.  A context-dependent attacker could
cause a buffer overflow with a specially crafted packet trace file,
resulting in a denial of service or potentially arbitrary code
execution.  (CVE-2014-2299)");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-01.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-02.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-03.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2014-04.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/lists/wireshark-announce/201403/msg00000.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 1.10.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Wireshark wiretap/mpeg.c Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '1.10.0', 'max_version' : '1.10.5', 'fixed_version' : '1.10.6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

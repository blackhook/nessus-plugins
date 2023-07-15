#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58518);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id("CVE-2012-1593", "CVE-2012-1594", "CVE-2012-1595", "CVE-2012-1596");
  script_bugtraq_id(52735, 52736, 52737, 52738);
  script_xref(name:"EDB-ID", value:"18758");

  script_name(english:"Wireshark 1.6.x < 1.6.6 Multiple Denial of Service Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark is 1.6.x before 1.6.6.  This
version is affected by the following vulnerabilities :

 - An error exists in the pcap and pcap-ng parsers that
   can allow them to crash when reading 'ERF' data.
   (Issue 6804)

 - An error exists in the IEEE 802.11 dissector that can
   cause it to go into an infinite loop. (Issue 6809)

 - An error exists in the 'ANSI A' dissector that can allow
   it to crash after dereferencing a NULL pointer.
   (Issue 6823)

 - An error exists in the 'MP2T' dissector that can allow
   it to allocate too much memory thus resulting in
   crashes. (Issue 6833)");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2012-04.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2012-05.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2012-06.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2012-07.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.6.6.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.6.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2023 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '1.6.0', 'max_version' : '1.6.5', 'fixed_version' : '1.6.6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

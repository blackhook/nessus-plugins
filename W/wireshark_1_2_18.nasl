#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55510);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id("CVE-2011-2597", "CVE-2011-2698");
  script_bugtraq_id(48150, 48506, 49071);
  script_xref(name:"Secunia", value:"45086");

  script_name(english:"Wireshark < 1.2.18 / 1.4.8 / 1.6.1 Multiple Denial of Service Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote host has an application that is affected by multiple 
denial of service vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Wireshark is earlier than 1.2.18 / 1.4.8 /
1.6.1 and thus is potentially affected by multiple denial of service 
vulnerabilities:

  - An error in the Lucent / Ascend file parser can be 
    exploited by specially crafted packets to cause high 
    CPU usage. (CVE-2011-2597)

  - An error in the 'elem_cell_id_list' function of the 
    ANSI MAP dissector can be exploited by a specially 
    crafted MAP packet to cause a denial of service 
    condition. (Issue #6044)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/wnpa-sec-2011-09.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/wnpa-sec-2011-10.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/wnpa-sec-2011-11.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Wireshark version 1.2.18 / 1.4.8 / 1.6.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/05");

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
  { 'min_version' : '1.2.0', 'max_version' : '1.2.17', 'fixed_version' : '1.12.18' },
  { 'min_version' : '1.4.0', 'max_version' : '1.4.7', 'fixed_version' : '1.4.8' },
  { 'min_version' : '1.6.0', 'max_version' : '1.6.0', 'fixed_version' : '1.6.1' }

];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

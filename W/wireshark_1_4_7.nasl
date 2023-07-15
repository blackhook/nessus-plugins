#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(54942);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2011-1956",
    "CVE-2011-1957",
    "CVE-2011-1958",
    "CVE-2011-1959",
    "CVE-2011-2174",
    "CVE-2011-2175"
  );
  script_bugtraq_id(48066);
  script_xref(name:"Secunia", value:"44449");

  script_name(english:"Wireshark < 1.2.17 / 1.4.7 Multiple DoS Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark is 1.2.x less than 1.2.17 or 1.4.x
less than 1.4.7.  As such, it is affected by the following
vulnerabilities :
  
  - An error exists in DICOM dissector that can allow denial
    of service attacks when processing certain malformed
    packets. (Issue #5876)

  - An error exists in the handling of corrupted snoop
    files that can cause application crashes. (Issue #5912)

  - An error exists in the handling of compressed capture
    data that can cause application crashes. (Issue #5908)

  - An error exists in the handling of 'Visual Networks'
    files that can cause application crashes. (Issue #5934)

  - An error exists in the 'desegment_tcp()' function in the
    file 'epan/dissectors/packet-tcp.c' that can allow a NULL
    pointer to be dereferenced when handling certain TCP
    segments. (Issue #5837)

  - An error exists in the handling of corrupted 'Diameter'
    dictionary files that can cause application crashes. 
    (CVE-2011-1958)");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5837");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5876");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5912");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5908");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5934");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2011-08.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2011-07.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.2.17.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.4.7.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.2.17 / 1.4.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/02");
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
  { 'min_version' : '1.4.0', 'max_version' : '1.4.6', 'fixed_version' : '1.4.7' },
  { 'min_version' : '1.2.0', 'max_version' : '1.2.16', 'fixed_version' : '1.2.17' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

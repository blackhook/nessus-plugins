#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134114);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/15");

  script_cve_id("CVE-2020-9428", "CVE-2020-9430", "CVE-2020-9431");
  script_xref(name:"IAVB", value:"2020-B-0011-S");

  script_name(english:"Wireshark 2.6.x < 2.6.15 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is prior to 2.6.15. It is, therefore, affected by multiple
vulnerabilities as referenced in the wireshark-2.6.15 advisory.

  - The LTE RRC dissector could leak memory. It may be
    possible to make Wireshark consume excessive CPU
    resources by injecting a malformed packet onto the wire
    or by convincing someone to read a malformed packet
    trace file. (wireshark-bug-16341) (CVE-2020-9431)

  - The WiMax DLMAP dissector could crash. It may be
    possible to make Wireshark crash by injecting a
    malformed packet onto the wire or by convincing someone
    to read a malformed packet trace file. (wireshark-
    bug-16368) (CVE-2020-9430)

  - The EAP dissector could crash. It may be possible to
    make Wireshark crash by injecting a malformed packet
    onto the wire or by convincing someone to read a
    malformed packet trace file. (wireshark-bug-16397) 
    (CVE-2020-9428)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.6.15.html");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=16341");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2020-03");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=16368");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2020-04");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=16397");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2020-05");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.6.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9428");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("installed_sw/Wireshark", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

constraints = [
  { 'min_version' : '2.6.0', 'max_version' : '2.6.14', 'fixed_version' : '2.6.15' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

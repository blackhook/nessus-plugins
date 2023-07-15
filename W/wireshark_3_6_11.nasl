#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170172);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2023-0411",
    "CVE-2023-0412",
    "CVE-2023-0413",
    "CVE-2023-0415",
    "CVE-2023-0416",
    "CVE-2023-0417"
  );
  script_xref(name:"IAVB", value:"2023-B-0008-S");

  script_name(english:"Wireshark 3.6.x < 3.6.11 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is prior to 3.6.11. It is, therefore, affected by multiple
vulnerabilities as referenced in the wireshark-3.6.11 advisory.

  - Memory leak in the NFS dissector in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of
    service via packet injection or crafted capture file (CVE-2023-0417)

  - Excessive loops in multiple dissectors in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial
    of service via packet injection or crafted capture file (CVE-2023-0411)

  - TIPC dissector crash in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of service via
    packet injection or crafted capture file (CVE-2023-0412)

  - Dissection engine bug in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of service via
    packet injection or crafted capture file (CVE-2023-0413)

  - iSCSI dissector crash in Wireshark 4.0.0 to 4.0.2 and 3.6.0 to 3.6.10 and allows denial of service via
    packet injection or crafted capture file (CVE-2023-0415)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-3.6.11.html");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/18628");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2023-02");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/18766");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2023-03");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/18779");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2023-04");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/18796");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2023-05");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/18737");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2023-06");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/wireshark/wireshark/-/issues/18770");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2023-07");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 3.6.11 or later.");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0417");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-0412");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("installed_sw/Wireshark", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '3.6.0', 'max_version' : '3.6.10', 'fixed_version' : '3.6.11' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

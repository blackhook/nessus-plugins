#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170000);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id("CVE-2022-4344", "CVE-2022-4345");
  script_xref(name:"IAVB", value:"2023-B-0004-S");

  script_name(english:"Wireshark 3.6.x < 3.6.10 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is prior to 3.6.10. It is, therefore, affected by multiple
vulnerabilities as referenced in the wireshark-3.6.10 advisory.

  - Infinite loops in the BPv6, OpenFlow, and Kafka protocol dissectors in Wireshark 4.0.0 to 4.0.1 and 3.6.0
    to 3.6.9 allows denial of service via packet injection or crafted capture file (CVE-2022-4345)

  - Memory exhaustion in the Kafka protocol dissector in Wireshark 4.0.0 to 4.0.1 and 3.6.0 to 3.6.9 allows
    denial of service via packet injection or crafted capture file (CVE-2022-4344)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-3.6.10.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2022-09");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2022-10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 3.6.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4345");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/12");

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
  { 'min_version' : '3.6.0', 'max_version' : '3.6.9', 'fixed_version' : '3.6.10' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

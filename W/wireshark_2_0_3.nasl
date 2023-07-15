#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90787);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2016-4006",
    "CVE-2016-4076",
    "CVE-2016-4077",
    "CVE-2016-4078",
    "CVE-2016-4079",
    "CVE-2016-4080",
    "CVE-2016-4081",
    "CVE-2016-4082",
    "CVE-2016-4083",
    "CVE-2016-4084"
  );
  script_xref(name:"EDB-ID", value:"39503");
  script_xref(name:"EDB-ID", value:"39604");
  script_xref(name:"EDB-ID", value:"39644");

  script_name(english:"Wireshark 2.0.x < 2.0.3 Multiple DoS");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is 2.0.x
prior to 2.0.3. It is, therefore, affected by multiple denial of
service vulnerabilities in the following components :

  - GSM CBCH dissector
  - IAX2 dissector
  - IEEE 802.11 dissector
  - MS-WSP dissector
  - NCP dissector
  - PKTC dissector
  - TShark");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.0.3.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4084");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("installed_sw/Wireshark");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '2.0.0', 'max_version' : '2.0.2', 'fixed_version' : '2.0.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

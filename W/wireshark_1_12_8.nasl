#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86480);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id("CVE-2015-7830");
  script_bugtraq_id(77101);

  script_name(english:"Wireshark 1.12.x < 1.12.8 pcapng File Parser DoS");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is
1.12.x prior to 1.12.8. It is, therefore, affected by a denial of
service vulnerability due to a flaw in the pcapng file parser that is
triggered when copying an interface filter. A remote attacker can
exploit this, via a specially crafted copy routine packet, to crash
the file parser.

Note that Nessus has not tested for this issues but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2015-30.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.8.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 1.12.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7830");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("installed_sw/Wireshark");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '1.12.0', 'max_version' : '1.12.7', 'fixed_version' : '1.12.8' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105007);
  script_version("3.7");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-17083", "CVE-2017-17084", "CVE-2017-17085");

  script_name(english:"Wireshark 2.2.x < 2.2.11 / 2.4.x < 2.4.3 DoS Vulnerabilities");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is 
2.2.x prior to 2.2.11 or 2.4.x prior to 2.4.3. It is, therefore, 
affected by denial of service vulnerabilities in the IWARP_MPA, 
NetBIOS, and CIP Safety dissectors. An unauthenticated, remote 
attacker can exploit this by injecting a malformed packet onto the 
wire or by convincing someone to read a malformed packet trace file.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-47.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-48.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2017-49.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.2.11 / 2.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-17085");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("installed_sw/Wireshark", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"Wireshark", win_local:TRUE);

constraints = [
  { "min_version" : "2.2.0", "fixed_version" : "2.2.11" },
  { "min_version" : "2.4.0", "fixed_version" : "2.4.3" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

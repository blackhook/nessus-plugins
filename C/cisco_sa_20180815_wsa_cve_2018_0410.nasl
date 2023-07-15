#TRUSTED 59620a642ba376222d74e83f16aa6da60188f54efb9bbc9b66317f727cfe06944c4df127a4cb93a2d4ddff315ce4272dca7a7b32fc639b3dc6958a06f2e4abfb53c714acbfd66ada80b25e5c82a399f87e0bb6af0e488bf9c311c8b26e4783d2ffd417ecdccf33c1683623e604a6fcdcf85d62eaa7714a3eed38de18b525c5a93c13a81e9f791d57021173384d523972fa76cbd1ccc8f07e3358c43e5f5c8332440fb5dfd0b48e182b94e66c20ba196bf3d5e86c71d9f6810af38ae3fc8dd651bc5dd1e23f414dba1ae3a703b4a5e50302945ee4ddfc7ae7acaa95a5f4f3de6c2319a9df8ee411de1f228d67cb3cd2524bc3daeb49563c42ba55244dc5f22559482e7440f4cd02054b411ccaf041fda1d41e194e50ec551ebbaaf9a9ae52127726713d72e930e8fd0577b3986de055342a0f00415990270f352f49f52a800084a3c477d4af11d139ede344e60a3215ccdd7fc8c515791f087f7c6f7d4b7d52dcaa187a45bf077460541c500a169eeefb675b00cab70278565ebbad2e9dd76b0aec33d08d649adc347481346a4056e6914f4cedc4065d7a6a6d2fbc8df1bf3911641f9320173d71886bd14ac0b84c7c79f3fc37bae0d28a81178501b86a815b6d5dbc4b46f8526b0a20f9c2fa965b19c050f8431d7c1c2bbddeb3301e7cc0a6975c639cc206277a138248772c1da453249eead9e5011b6f2e3bf255934a073d94
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112121);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/14");

  script_cve_id("CVE-2018-0410", "CVE-2018-0428");
  script_bugtraq_id(105098);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf36610");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj93548");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180815-wsa-dos");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180815-wsa-escalation");

  script_name(english:"Cisco Web Security Appliance Multiple Vulnerabilities.");
  script_summary(english:"Checks the WSA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote security appliance may be affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Web Security
Appliance (WSA) running on the remote host may be affected by multiple vulnerabilities.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180815-wsa-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48e095b0");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf36610
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1bb57639");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180815-wsa-escalation
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87dd52c9");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj93548
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9bd6384");
  script_set_attribute(attribute:"solution", value:
"Apply the vendor supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0428");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");


product_info = cisco::get_product_info(name:"Cisco Web Security Appliance (WSA)");
workarounds = make_list(CISCO_WORKAROUNDS["no_workaround"]);
workaround_params = make_list();

vuln_ranges = [
  { "min_ver" : "1.0.0.0", "fix_ver" : "10.1.3.054" },
  { "min_ver" : "10.5.0.0", "fix_ver" : "10.5.2.072" },
  { "min_ver" : "11.0.0.0", "fix_ver" : "11.5.0.614" }
];

reporting = make_array(
  "port"     , 0,
  "severity" , SECURITY_HOLE,
  'bug_id'   , "CSCvf36610 & CSCvj93548",
  "version"  , product_info["display_version"],
  "fix"      , "See advisory"
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);

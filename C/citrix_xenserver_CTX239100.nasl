#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118856);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-18883");
  script_bugtraq_id(105817);

  script_name(english:"Citrix XenServer Nested VT-x Instruction Guest-to-Host DoS (CTX239100)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"A server virtualization platform installed on the remote host is
missing a security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer running on the remote host is missing
a security hotfix. It is, therefore, affected by by a guest-to-host
denial of service vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX239100");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18883");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:xenserver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_xenserver_version.nbin");
  script_require_keys("Host/XenServer/version", "Host/local_checks_enabled", "Settings/ParanoidReport");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

app_info = vcf::xenserver::get_app_info();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

constraints = [
  { "equal" : "7.1.1",  "patches" :           # XenServer 7.1 LTSR CU1
                          ["XS71ECU1031"] },  # CTX239126
  { "equal" : "7.5",    "patches" :           # XenServer 7.5
                          ["XS75E006"] },     # CTX239127
  { "equal" : "7.6",    "patches" :           # XenServer 7.6
                          ["XS76E001"] }      # CTX239128
];

vcf::xenserver::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

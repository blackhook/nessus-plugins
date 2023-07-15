#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110812);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2018-9185");
  script_bugtraq_id(102151, 104288, 104312);

  script_name(english:"Fortinet FortiGate < 5.6.6 / 6.0.x < 6.0.1 Plain Text Credentials (FG-IR-18-027)");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running FortiOS prior to 5.6.6 / 6.0.x < 6.0.1.
It is, therefore, affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-18-027");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version 5.6.6, 6.0.1, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-9185");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include("audit.inc");
include('vcf.inc');
include('vcf_extras_fortios.inc');

app_name = "FortiOS";

app_info = vcf::get_app_info(app:app_name, kb_ver:"Host/Fortigate/version");

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

constraints = [
  { "max_version" : "5.6.5", "fixed_version" : "5.6.6" },
  { "min_version" : "6.0.0", "fixed_version" : "6.0.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

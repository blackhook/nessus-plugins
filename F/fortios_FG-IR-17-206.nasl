#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104352);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id(
    "CVE-2017-14182"
  );
  script_bugtraq_id(101559);

  script_name(english:"Fortinet FortiOS 5.4.x < 5.4.6 Denial of Service (FG-IR-17-206)");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a Denial of Service (DoS) vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Fortinet FortiOS running on the remote device is 5.4 prior
to 5.4.6. It is, therefore, affected by a Denial of Service (DoS) 
vulnerability in the FortiOS webUI.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-17-206");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version 5.4.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14182");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2017/10/24");
  script_set_attribute(attribute:"patch_publication_date",value:"2017/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/02");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

app_info = vcf::get_app_info(app:"FortiOS", kb_ver:"Host/Fortigate/version");

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

constraints = [
  # 5.4.0 < 5.4.6
  { "min_version" : "5.4.0", "fixed_version" : "5.4.6" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

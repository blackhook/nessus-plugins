#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112183);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2018-1353");

  script_name(english:"Fortinet FortiManager < 6.0.2 Information Disclosure Vulnerability (FG-IR-18-016)");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of FortiManager running on the remote device is prior to
6.0.2. It is, therefore, affected by an information disclosure
vulnerability. A user with an adom assignment can potentially read
the settings of other vdoms.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-18-016");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiManager version 6.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1353");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortimanager_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

app = 'FortiManager';

vcf::fortios::verify_product_and_model(product_name:app);

app = "FortiManager";
# Using kb source to grab the model to check for FortiAnalyzer / FortiManager
app_info = vcf::get_app_info(app:app,
                              kb_ver:"Host/Fortigate/version",
                              kb_source:"Host/Fortigate/model");

constraints = [{"fixed_version" : "6.0.2"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

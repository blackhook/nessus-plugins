#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124328);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2018-1360");

  script_name(english:"Fortinet FortiManager Unencrypted Password Vulnerability (FG-IR-18-051)");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of FortiManager running on the remote device is 5.2.x 
and prior to 5.2.8 or 5.4.x and prior to 5.4.2. It is, therefore, 
affected by an information disclosure vulnerability due to a 
cleartext transmission of sensitive information in the REST API json
responses. A user performing a man in the middle attack would be able
to retrieve the admin password.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-18-051");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiManager version 5.2.8 / 5.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1360");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date",value:"2019/04/23");
  script_set_attribute(attribute:"patch_publication_date",value:"2019/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/26");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:fortinet:fortimanager_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

constraints = [
               {"min_version" : "5.2.0", "fixed_version" : "5.2.8"}, 
               {"min_version" : "5.4.0", "fixed_version" : "5.4.2"}
               ];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119421);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2018-13376");
  script_bugtraq_id(106036);

  script_name(english:"Fortinet FortiGate 5.2.x >= 5.2.12 / 5.4.6 - 5.4.7 / 5.6.1 - 5.6.3 Information Disclosure (FG-IR-18-325)");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running FortiOS 5.12.x greater than or equal to
5.2.12, 5.4.6, 5.4.7, 5.6.1 up to 5.6.3. It is, therefore, affected by
an error related to the web proxy disclaimer web pages that allows
disclosure of uninitialized memory buffers.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-18-325");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version 5.4.8, 5.6.4, 6.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-13376");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/05");

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
  # 5.2.12 and up for remainder of 5.2.x
  { "min_version":"5.2.12", "fixed_version" : "5.3", "fixed_display" : "5.4.8" },
  # 5.4.6 and 5.4.7
  { "min_version":"5.4.6", "max_version" : "5.4.7", "fixed_version" : "5.4.8" },
  # 5.6.1 up to and including 5.6.3
  { "min_version":"5.6.1", "max_version" : "5.6.3", "fixed_version" : "5.6.4 / 6.0.0" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

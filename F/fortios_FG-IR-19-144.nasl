#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139547);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_name(english:"Improper Check for Certificate Revocation (FG-IR-19-144)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an improper check for certificate revocation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by an improper check for certificate revocation vulnerability. Certificates taken out
of service could potentially be improperly re-used.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-19-144");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version 5.2.14 or 5.4.12 or 5.6.10 or 6.0.6 or 6.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

app_name = 'FortiOS';

app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

constraints = [
  { 'max_version' : '5.2.13', 'fixed_version' : '5.2.14' },
  { 'min_version':'5.4.0', 'max_version' : '5.4.11', 'fixed_version' : '5.4.12' },
  { 'min_version':'5.6.0', 'max_version' : '5.6.9', 'fixed_version' : '5.6.10' },
  { 'min_version':'6.0.0', 'max_version' : '6.0.5', 'fixed_version' : '6.0.6' },
  { 'min_version':'6.2.0', 'max_version' : '6.2.0', 'fixed_version' : '6.2.1' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);

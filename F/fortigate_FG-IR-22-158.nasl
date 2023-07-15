#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165242);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/02");

  script_cve_id("CVE-2022-29053");

  script_name(english:"Fortinet Fortigate - Flaws over krb keytab encryption scheme (FG-IR-22-158)");

  script_set_attribute(attribute:"synopsis", value:
"Fortinet Firewall is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of Fortigate installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-22-158 advisory.

  - A missing cryptographic steps vulnerability [CWE-325]in the functions that encrypt the keytab files in
    FortiOS may allow anattacker in possession of the encrypted file to decipher it. (CVE-2022-29053)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortigate version 7.0.6 / 7.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29053");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version", "Host/Fortigate/model");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

var app_name = 'Fortigate';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:app_name);

var constraints = [
  { 'min_version' : '6.0.0', 'fixed_version' : '7.0.6' },
  { 'min_version' : '7.2.0', 'max_version' : '7.2.0', 'fixed_version' : '7.2.1' }
];

vcf::fortios::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);

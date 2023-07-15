#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(131185);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2019-5593");

  script_name(english:"Fortinet FortiOS < 5.6.11 / 6.0.0 < 6.0.7 / 6.2.0 < 6.2.2 Information Disclosure (FG-IR-19-134)");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiOS prior to 5.6.11, 6.0.x prior to 6.0.7, or 6.2.x prior to 6.2.2. It is,
therefore, affected by an information disclosure vulnerability. The vulnerability exists in the storage of private keys
and certificates due to improper value checking or permissions. A non-privileged, local attacker can exploit this via
the CLI by unsetting a private key's encryption password for builtin system certificates or setting a blank password
for user uploaded certificates. The attacker can use this to disclose plaintext private keys.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-19-134");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version to 5.6.11, 6.0.9, 6.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5593");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/version");

  exit(0);
}

include('audit.inc');
include('vcf.inc');
include('vcf_extras_fortios.inc');

app_name = 'FortiOS';
app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

constraints = [
  { 'fixed_version':'5.6.11'},
  { 'min_version':'6.0.0', 'fixed_version':'6.0.7'},
  { 'min_version':'6.2.0', 'fixed_version':'6.2.2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);

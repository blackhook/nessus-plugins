#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130209);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2019-15703");

  script_name(english:"FortiOS DRBG unsufficient entropy (FG-IR-19-186)");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"An Insufficient Entropy in PRNG vulnerability in Fortinet FortiOS 6.2.1 and below for device not enable
hardware TRNG token and models not support builtin TRNG seed allows attacker to theoretically recover the
long term ECDSA secret in a TLS client with a RSA handshake and mutual ECDSA authentication via the help
of flush+reload side channel attacks in FortiGate VM models only.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-19-186");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version 6.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15703");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('vcf.inc');
include('vcf_extras_fortios.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = 'FortiOS';

app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

constraints = [
  { 'fixed_version' : '6.2.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);

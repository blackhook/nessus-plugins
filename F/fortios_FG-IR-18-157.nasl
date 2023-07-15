#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121356);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2018-13374");
  script_bugtraq_id(106686);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/29");

  script_name(english:"Fortinet FortiGate < 5.6.8 / 6.x < 6.0.3 LDAP Credential Disclosure (FG-IR-18-157)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a credential disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running FortiOS prior to 5.6.8 or 6.x prior to
6.0.3. It is, therefore, affected by a credential disclosure
vulnerability in the LDAP connectivity test component. This can allow
a remote, read-only admin authenticated attacker to obtain the
configured LDAP server login credentials by pointing the LDAP
connectivity test at a rogue LDAP server they control.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-18-157");
  # https://plaintext.do/My-1st-CVE-Capture-LDAP-Credentials-From-FortiGate-EN/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?144f85d4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version 5.6.8, 6.0.3, or 6.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-13374");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  # FortiOS 5.6.7 and before
  { "max_version":"5.6.7", "fixed_version":"5.6.8" },
  # FortiOS 6.0.0 -> 6.0.2 
  { "min_version":"6.0.0", "max_version":"6.0.2", "fixed_version":"6.0.3" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

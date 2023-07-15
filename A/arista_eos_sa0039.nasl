#TRUSTED 3cab66353acc7709262817629dabd48499b75a9abbe1dfe8bb4544562f3ad48817386852d679ef699f2d83592d46b956eb6b840ed7d78f7dd8c7f54ebdca8eeaca62258d06ddc4f004af85a605062ae8e751cd61da99f4e7f9e5d87ef92b33ad14b482dfecd1c6e84c857898c47b9f098738ec509cc26749f5b253bd43c1735ef4fc99e9437dd40b37bdbe80d4f24545a3691bf45050886a8cdaaa4f2bedfb36c1b0916251ca40a7eba9b4ff47b50a045f42847da7d824fff4f4738cca37c2b6c8012ac39ca8e2286bebc8d6b1b9535355b2add532df121c6b15e0a13238e7021520d825cea6e3119ab5fa84205809af504154f6aa08ba1f978669e30a4ce382103899e12c799392fe8470d09977357ef09f1249637c2a3cb9ca2c1572a73d2e464a5686652f0426600fe556e216ae7dcd6946de2d79094d738617a8545170a4b0c5fce098b56cee26df3a4b6c1f9a59ab4e8aab4def53d7e610682493132ff4edbff7ccf5416f6255148cc9da13781df6bcde871a9ddb1ede17afc1caa2dc7c0f56781739a32150dcf91f476bf85f967578daa4227428d1ad7dc8bcd06199748708de77711a5449af7e166fc61192c8bcad4ce6775f08c0a9b041864b5953961791ef2b916534454cf28ee1ba5105835593ceb659afbff2c9fba675e3e996eb2c6916d2044e1accf9f6e33c7be8cc7e80c8bb5330ba227a21b0f03b359fb0ce
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134116);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/06");

  script_cve_id("CVE-2018-16875");
  script_bugtraq_id(106230);

  script_name(english:"Arista Networks EOS DoS (SA0039)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is affected by a denial of service (DoS) vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is affected by a denial of service (DoS) vulnerability
in the client certificate authentication process, due to the crypto/x509 package in Go not limiting the amount of work
performed for each chain verification. A remote, unauthenticated attacker can exploit this, by sending a crafted
certificate to cause the system to stop responding.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/6401-security-advisory-39
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f5f296e9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Arista Networks EOS version 4.21.4F or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16875");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arista:eos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arista_eos_detect.nbin");
  script_require_keys("Host/Arista-EOS/Version", "Settings/ParanoidReport");

  exit(0);
}

include('arista_eos_func.inc');
include('audit.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = get_kb_item_or_exit('Host/Arista-EOS/Version');

vmatrix = make_array();
vmatrix['F'] = make_list('4.21.3');

vmatrix['fix'] = '4.21.4F';

if (eos_is_affected(vmatrix:vmatrix, version:version))
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:eos_report_get());
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Arista Networks EOS', version);

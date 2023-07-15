#TRUSTED 1a2561a111cf9ff1bfee35d21dc864bfef1e026f372a9385ac408f4e3c3c58f36887f66d523af95afd65ca9b6b1949fc2630082e92fc0b81160e6519ac60a57e1265e17efd6996f28b6f2bac410187b634780c5d151d250088588e1dbfffecec3a5fd75b1ce2bc8a87ef48c3e1513ba729b7e56d643e3ffb2030e547b838d93e867e5ebc99306a8ee69dbec1ea8be06ad3c744e03344b4bd3509f040030e7de846eae57ee8983366c019b8f425a0a282987ab6be1086b9dffd4f45272b72d4cc236f4ce06ce9a75a9bd26064abdd423f366aefd18494ab5b363776880bae0078fc5a1e23360d3bbb7b42042e766913bb879a5aa169576e3496edd889723c7c1fbcc696df12e0fc2e7760f8daa73bcdb89980327b3d6579dfc04bde25d1373bf99715a37d1f5343c3e2320e5ac2bee6a780b336145b6ea039ed353c43b298e0c64e674223c45b779e31ab9adae3fc1c173447151f10b6f7fb15dd82ab0e86af591a4058ffd69b848e63af70e37de4236f5f00094449922539c7d3834e0667d724cb11ecf59681509cbdb422c5483d89517a8e053e0a1ccd4771991c8e451507e2a3d5fc0437c58eba0aa64908ebcbfd9ae973228f67117d81c0ccd9872caf2791de0211066875b62dd11c56c1ca4bd89f653dbde11e691539ca5e72458d91dbd3d5ce088205cf104d3e82d3c68dc1909680dde06eb978061b59aa722f4fe47d6a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94291);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2016-6431");
  script_bugtraq_id(93786);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz47295");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20161019-asa-ca");

  script_name(english:"Cisco ASA Certificate Authority Enrollment Operation Packet Handling DoS (cisco-sa-20161019-asa-ca)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
Adaptive Security Appliance (ASA) software running on the remote
device is affected by a denial of service vulnerability in the
Certificate Authority (CA) feature due to improper handling of packets
during the enrollment operation. An unauthenticated, remote attacker
can exploit this, via a specially crafted enrollment request, to cause
the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161019-asa-ca
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c05f684");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz47295");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20161019-asa-ca.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

version = extract_asa_version(asa);
if (isnull(version)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (
  model !~ '^55[0-9][0-9]($|[^0-9])' && # 5500 & 5500-X
  model !~ '^93[0-9][0-9]($|[^0-9])' && # Firepower ASA
  model !~ '^41[0-9][0-9]($|[^0-9])' && # Firepower ASA
  model !~ '^30[0-9][0-9]($|[^0-9])' && # ISA 3000
  model !~ '^(1000)?v$'                 # reported by ASAv
) audit(AUDIT_HOST_NOT, "an affected Cisco ASA product");

cbi = 'CSCuz47295';

if (version =~ "^8\.[012346][^0-9]")
  fixed_ver = "9.1(7.7)";

else if (version =~ "^9\.0[^0-9]" && check_asa_release(version:version, patched:"9.0(4.42)"))
  fixed_ver = "9.0(4.42)";

else if (version =~ "^9\.1[^0-9]" && check_asa_release(version:version, patched:"9.1(7.7)"))
  fixed_ver = "9.1(7.7)";

else if (version =~ "^9\.2[^0-9]" && check_asa_release(version:version, patched:"9.2(4.13)"))
  fixed_ver = "9.2(4.13)";

else if (version =~ "^9\.3[^0-9]" && check_asa_release(version:version,patched:"9.3(3.11)"))
  fixed_ver = "9.3(3.11)";

else if (version =~ "^9\.4[^0-9]" && check_asa_release(version:version,patched:"9.4(3.6)"))
  fixed_ver = "9.4(3.6)";

else if (version =~ "^9\.5[^0-9]" && check_asa_release(version:version, patched:"9.5(3)"))
  fixed_ver = "9.5(3)";

else if (version =~ "^9\.6[^0-9]" && check_asa_release(version:version, patched:"9.6(1.5)"))
  fixed_ver = "9.6(1.5)";

else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);

override = FALSE;
flag = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show crypto ca server", "show crypto ca server");

  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"State *: *enabled", string:buf))
      flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because the Certificate Authority feature is not enabled");
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : version,
    bug_id   : cbi,
    fix      : fixed_ver,
    cmds     : make_list("show crypto ca server")
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);

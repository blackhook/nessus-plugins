#TRUSTED 051b203023083649e4ff44817783a2ad3894103825e148f43fb61a6b9b41ecf03d15072d37a0022f7f42fc8f4efadf35c4e3688874709ed18e94f927ffcb55310128c13aa6f9ab66dae56e85d38bd212495e02ab36f0eade7fa1accc9d01af36c4ad7d2e4d53f3c513b25fc8216e50464196e8516956147c4f8a057579975eaf888e3e15e8f9a4d367bb5f6c28021a29fd2bb071a840c3afa87ca9331ac5ceee580e6f4746c846abbed631ed7ea5da685a395d6aacb8159027e77f6bab13cd875adc3a035b903b5f65eddf27540e81e186f89b04ea4602e6f2417b573a12817426a4da17b528a86db989225148d45b0d6c8b112a7f21850f01c61af563e00ce7079ce7115ebe339f07fb63fd0b27256d670919c9b3ba55d5f8a7e83b970134f90cabe90c2df3790d9bef5220552b973904225ed55d9bb67fbaa1adf2cc4ba347034ce4b51db870eb8c06dff92fcfbad623ef3e9acd7e2c1bf3acc4db10b6aec07cbd1e38ee3910ccf3bf911f1fe6baf8f389a5e96c3bd6c7b555282bb8df3ae68b09d6aef0edf39121c111cfa1b9de12a2f10de5f366e7e1b22c39757839833c2c7323afb4ae2aa8f19874e4d7a81409102c673fc58bcb763641e19cbeddba513ddcf8290fa0146aad7efb70077f7cd712a0315188166b4c7f776680397cc641156c77ad788300b58113a8562199bc29058cbbf907759bc5d472f0b336ff297a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99668);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-6610");
  script_bugtraq_id(97934);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz11685");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170419-asa-xauth");

  script_name(english:"Cisco ASA Software IKEv1 XAUTH Parameter Handling Remote DoS (cisco-sa-20170419-asa-xauth)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
Adaptive Security Appliance (ASA) software running on the remote
device is affected by a denial of service vulnerability in the
Internet Key Exchange Version 1 (IKEv1) XAUTH code due to improper
validation of the IKEv1 XAUTH parameters passed during an IKEv1
negotiation. An authenticated, remote attacker can exploit this, via
specially crafted parameters, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-asa-xauth
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6b8b6cb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20170419-asa-xauth.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6610");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  model !~ '^1000V' && # 1000V
  model !~ '^55[0-9][0-9]($|[^0-9])' && # 5500 & 5500-X
  model !~ '^65[0-9][0-9]($|[^0-9])' && # 6500
  model !~ '^76[0-9][0-9]($|[^0-9])' && # 7600
  model !~ '^93[0-9][0-9]($|[^0-9])' && # Firepower 9300 ASA
  model !~ '^30[0-9][0-9]($|[^0-9])' && # ISA 3000
  model != 'v' # ASAv
) audit(AUDIT_HOST_NOT, "an affected Cisco ASA product");

cbi = 'CSCuz11685';

if (version =~ "^[0-8]\.")
  fixed_ver = "9.1(7.7)";
else if (version =~ "^9\.0[^0-9]")
  fixed_ver = "9.1(7.7)";
else if (version =~ "^9\.1[^0-9]" && check_asa_release(version:version, patched:"9.1(7.7)"))
  fixed_ver = "9.1(7.7)";
else if (version =~ "^9\.2[^0-9]" && check_asa_release(version:version, patched:"9.2(4.11)"))
  fixed_ver = "9.2(4.11)";
else if (version =~ "^9\.3[^0-9]")
  fixed_ver = "9.4(4)";
else if (version =~ "^9\.4[^0-9]" && check_asa_release(version:version, patched:"9.4(4)"))
  fixed_ver = "9.4(4)";
else if (version =~ "^9\.5[^0-9]" && check_asa_release(version:version, patched:"9.5(3)"))
  fixed_ver = "9.5(3)";
else if (version =~ "^9\.6[^0-9]" && check_asa_release(version:version, patched:"9.6(1.5)"))
  fixed_ver = "9.6(1.5)";
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);

override = FALSE;
flag = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show running-config crypto map | include interface|dynamic", "show running-config crypto map | include interface|dynamic");
  cmd = make_list("show running-config crypto map | include interface|dynamic");
  if (check_cisco_result(buf))
  {
    auditmsg = "affected because a dynamic crypto map is assigned to an interface";
    if ("dynamic" >!< buf || "interface" >!< buf)
    {
      buf2 = cisco_command_kb_item("Host/Cisco/Config/show running-config all tunnel-group | include xauth", "show running-config all tunnel-group | include xauth");
      cmd = make_list(cmd,"show running-config all tunnel-group | include xauth");
      if (check_cisco_result(buf2))
      {
        auditmsg = "affected because XAUTH is not in use";
        if ("ikev1 user-authentication xauth" >< buf2)
          flag = TRUE;
      }
    }
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, auditmsg);
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    override : override,
    version  : version,
    bug_id   : cbi,
    fix      : fixed_ver,
    cmds     : cmd
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);

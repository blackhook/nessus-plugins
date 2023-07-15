#TRUSTED 392cb70799518fa8db8892891199c7537ad81119ab80530eebc0a4c6c585acfc9c6975ae736e157db6346dbd6d2d33feb95a407e4a074f64b06d06be8a754eaa3073a38ba9c281f0916609ab957860dd4fbb3bd12ee336c26f1315559049af00cae7108d43b1a9db8468d0456edff86c273b5ef49e88efb1abfade6afa98c1c258089eae8398d8bc37fb3113ce16d4d542d96dc0b74f37ec4ccf606c9c6c8e1b359088da81cade509b4559b53a7907993cc8d309c446bf2d14d92c1d1d639c81871cc11288a2cf23350734f414d44f4484603abc5ac31fc27de7798d74afeec6d3394cdf4af0dc0c8c5b94631e8b718c2735c71a458800f2b705a7d6725d67f9324dd9a1174fadfa79bab989212c03c8f84ba5ae07aeb3a6b7b368c5d89b684642dd93b76b443979649b3723809436d740692dac5c76786d67b0f20af4acb416d454fff5f4e0ab0651ec367ec31cf19e2c52c04bdd946273c217a7b53ff1b64e46ea5dd8c834da067eb9955b0571d2f1e4684e5c988bdafd22859dec1c5c7305ade98ba17ce6185e70de520504cabf566b1185f1368ac14333359db30ceb9049a41c097a5ec6728dadf72350f9f3515cb81c9addc1204723282f865539ca1fc242b51dfcf8e1e1f31510476ff2e6d1ce44d62841a896d3e322374242ed652dc7c72b9c83dc8d953a0ccff6ce4c0be6b0887682878e87c84525030897e521926e
#TRUST-RSA-SHA256 7ae3f12a03ca9f6dff01b8a4843b5ddd86b68fd4e2ac9c7c4eec7538150ff8082382bd718d92bc155b093d1d009d6118e09d4397e4fb46326d2b295a3a41903c38eb61e8f5a72506496c097ffdd51467c430e97d2eac0308c5f7ec116b0e6c04a277c5f7401d2311e7d47b19bc0fe59e06dcd0b830901947537bdd65645dd85d5603c565abac0dddbd6819be826f1764fdb9309bf9f1dad176eb01eee115737478434bb156e05005dea574146e62d2ef93919d327b06b071f2e177476c117a397ca819ac63b6c4ec8f18d2e568869a6058698b15c5452e39ea94092a830319728874394a41dbe7534eec3ea6cdcadefd60a39e995bd00c49a768c86cf32307823ffef4cea13cf753a7cbb144141f6ffbed4558904ad0122735c64146258df79fda1a7595f3fe698ae945a322eed6491702ed3df059aedf4ed7af0c7d907b7ba2e943fdf681070fc5cb0db9a393b245598c916448601c4cbdbd509b2acc226610da305b44a334c92f21aa4338bbef90565ae8314f2d6ec3b4abdcd44f93444a028beff034547792c5966e27cbb4fd8f5f2834a3777db48757838d26c1822dfd93546fd071987f5ada21a505ca38fc05fb38801dac5e5c807721c4c2afc350513ffc8c13492bd528cafd90daa14d7fdef9fd1b91d205544e4b6996ccdf12e3e92ed53c9c7298ada1658bf77487fa9372a5e053a5793f5418b356b08bf72e2efd5d
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168964);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/23");

  script_cve_id("CVE-2022-22228");
  script_xref(name:"JSA", value:"JSA69880");
  script_xref(name:"IAVA", value:"2022-A-0421");

  script_name(english:"Juniper Junos OS Vulnerability (JSA69880)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA69880
advisory.

  - An Improper Validation of Specified Type of Input vulnerability in the routing protocol daemon (rpd) of
    Juniper Networks Junos OS allows an attacker to cause an RPD memory leak leading to a Denial of Service
    (DoS). This memory leak only occurs when the attacker's packets are destined to any configured IPv6
    address on the device. (CVE-2022-22228)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  # https://supportportal.juniper.net/s/article/2022-10-Security-Bulletin-Junos-OS-On-IPv6-OAM-SRv6-network-enabled-devices-an-attacker-sending-a-specific-genuine-packet-to-an-IPv6-address-configured-on-the-device-may-cause-a-RPD-memory-leak-leading-to-an-RPD-core-CVE-2022-22228
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?88ad5bd4");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69880");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22228");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S2'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S1'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R2'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R2'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set routing-options source-packet-routing srv6 locator")
   || !junos_check_config(buf:buf, pattern:"^set protocols isis source-packet-routing node-segment ipv6-index")
   || !junos_check_config(buf:buf, pattern:"^set protocols isis source-packet-routing srv6 locator.*end-sid.*flavor")
   || !junos_check_config(buf:buf, pattern:"^set protocols mpls interface all")
   || !junos_check_config(buf:buf, pattern:"^set interfaces.*unit.*family inet6 address")
   )
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);

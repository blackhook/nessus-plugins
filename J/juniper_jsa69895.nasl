#TRUSTED 662ae04d08eb20c54e1ea686efbe6cbdede469e6312010283f97eeff3ca2fde1bf35fa0d88ff6d0a367010837241ed44921d5e49743beaf352bb1cc05add884b28485690e95d7a3eb6268d57129d674b19b3d80422b1ec22b5d404f905f53e0eeb9080922286c7ec8633b86375ac1db18ce9fbb55935b084de27aa54313e13e598c806ae10670e23e4143ba61070d3294677c84babb6bcaa419e3536ab0831754b71e1ed3c23f3a82665889e6881d6910438e83ffb319e8fde59aae49a498b60709602fb615c53d6cfe4a80e9c65f8070db1e079b2837061ed5edc96014c414d388d98aa89d5571c2da42851dd126b83930e2a3ae91e8d16123408e94bdea4cb59ba9bd440f6b31ef61a31a6aa18444993f8bedd307f71ebb550ecd320efcfa24a197afb3b21a918256afb235e4392523b7afaf4aea2c49ec587a783392dbe4d7a951d6249ba7c4c42511c7d7dcb34c92cecf9d8f9a1e7e32f245c0a35a652f8e045786d6085b1f79260925211a36df3db4e75790f2a2f58223ce7c549e3bca5699d1963d83226627f4aca7a20225a6c8a759eb9e3e4db566d215b7287e41bdb006c9c31385b7ba313e16b54b5a24f789c4bd310e8d278b79d90d58b6cc106a340131c282e7486a6256c7ff48f903483eb1f48d9e70835bd31943848a397fb458229b7b822d81cf8af426d2b1f73b78d2a0df3a16803539babbee454547c000c
#TRUST-RSA-SHA256 79217d5e6b4fb4aa7d68363a9f262c3aea089c6f7b4aee168be886b96026f6c470f57f6867d5ff83ab48203159becd76985ef1e641193450d38123aec2a4691534b9e4200eb6fc856e9e60b7611fc22160fcde0137d7ba8c8c7cfcc6a557d0bcef40b8b103adf99f70a7443ba738c4aae294f9e4208d8cf213c128bf4a190796753a8fdacc478a89a5b01a951dbffaa2d001d0c12a1c1a3bea112e45a188ef81302521a8e04f5562a26ab07d742b4765aab1ee058e74f18937c017e4e865f5eefc15a4a276601fdcb5abe65db63030957185bba50d17339f88372c5eec38636a6fbd4dbbf0f5dff52deaf5ce167d66f30f152253e155cc1a18af1145b35f7eaf3860962b156a99d5e2c661c3354339e0890ff2a2519086c6f94c7289707352c45c068531979aea1f75e6f9bf828b4d0e87c41ae7d253daf9f89a21b1d7d345ba1d1b04d959747d3abbe9c024ed062f78666cee714d3fb9e9c71288a3aa3554acc3f5dc86d2859fe7367e9d797ba09f8c3c971bc8b896d03a96c77b90648a3a4adc3706fa7c550b34e68307b9397ad7b38d4f015f003fd88dba0402afff401bb2789613c8b51cf7fee1a55aaeaa7025598804feb1ebc7e35267b0649d63db69558b099979ca5ab570a4ece43c18fc27c053c57d4eff6b5b138b84f979c7c1b73e57210a6dd0e7269fb892f056ddb14f222a803169f6cf679aacc3a48a5011d9cc
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166324);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/28");

  script_cve_id("CVE-2022-22239");
  script_xref(name:"JSA", value:"JSA69895");
  script_xref(name:"IAVA", value:"2022-A-0421");

  script_name(english:"Juniper Junos OS Privilege Escalation (JSA69895)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a privilege escalation vulnerability as
referenced in the JSA69895 advisory. An Execution with Unnecessary Privileges vulnerability in Management Daemon
(mgd) of Juniper Networks Junos OS Evolved allows a locally authenticated attacker with low privileges to escalate
their privileges on the device and potentially remote systems.

A workaround for this issue is to modify the applicable login class(es) so that the ssh command can not be accessed
anymore. This can be done by removing the 'network' permission or modifying the resp. allow-/deny-commands
configuration.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  # https://supportportal.juniper.net/s/article/2022-10-Security-Bulletin-Junos-OS-Evolved-The-ssh-CLI-command-always-runs-as-root-which-can-lead-to-privilege-escalation-CVE-2022-22239
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f66b8bb");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69895");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22239");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/20");

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

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0', 'fixed_ver':'20.4R3-S5-EVO'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-EVO'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R2-S1-EVO', 'fixed_display':'21.2R2-S1-EVO, 21.2R3-EVO'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
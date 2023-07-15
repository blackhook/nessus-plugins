#TRUSTED a89cc26161fe73e14ced7489909c49ef8e4d496d5f1c258f3f4d026b2816cf909a2630fdcf9b467d95c638bf5ebb2ca9941b2b82b18794ae28db53fd417ee45b8911b4ce9783a3e4fbeb85b2c6ff404aa14719817ed558d97d36bb2fbd324ca850ca87175701d26b4d1c875f631c84b444bc01b489c22a1946ae00f42305fc82f39a16d58a552cdc90c51fda4a491b3da751ba88083458cf4355ee01cb0b5a7cfe761d6e81763a426324a7564ae730dfe12596b93d040be33c7d561f6feda264f219e9bf47ea2cab17b0e1b56d66f8d41ec6780fe5716e41131a64d4381f894a835766f553317e2f0d274ca4fae09cf87f7b9cf7e7b4ebf55777f158d0e26bd1bdafa220c558ce3b676e3a0154a1697f582a3b11126ed62f22fbd259f4b6e588f8a845de91214dbf8d68060acb9c713645b9c964404eb2c3f1eef196ffd2141526e7e1debe772a0417f94da07bdbb3d5cfd214812f2038cdb59db113a8fd3f445fcf6b4beef03cd2cb94ece99d2960464eba2b2f49bcf57045e32b99841d1e226261c85c664c666c2d1b7231f2df73fb6fdbb1067e9af60de2dee1488b1320c5585638bf194883fef2860863a922092a582fb404f40e66002968bc3b79e1dd097f222061af909e0c0bacf6bccfae1e1fd4842fd874ef3682bdf1d0b41e6722a46f1a6c08c5bd69cfb37caf87e683974d6179dea5b3a02cb987099255326eb174
#TRUST-RSA-SHA256 a934c5c93d96a6d0aa20e9bb00b020e355496abb8ea01aa2335c2a2a21a44c3dff8a14bf9f6bfa052a7331354c75cfa367d6567b2e039aea6a989a58b9efe39068fc3dfe53cd7843d63720d77559db4f87e5692bac5ef08c347d505034aa71b7661da0aa5a70208b6ebbc25c66971890cb54518e1c20391e4da1a206c4621f891bbf71fd65edd1cb5e665d6ddf7c446e529aa5425fc901674539a7f13e878f185c9cc6f0805ba06b6afd987e185078e52cd08bb912610b4f4fd103c41ee8879af55b778635351224944896c0cb25c5e4e933b3a143f9482d57522625ac50e725755b4e32427122e43043a9d1042d1f6ee4a9320699ec66e14b26fdda1e98aa13d6a120ea17325a9a86f4035632abeb06cf2634ce10e41a7164c3d2acae4c205334f8cb162f66d29c3f964111b13f8e013a8f427b092acabe1d4b12c8a3886c68b45fe92cc178c0ceb8b3a78c25c4c133a7d733943be4952d0d82515f3dc0f637fe695db32ca31156dbab21433173a46cc6c228b33ae52579df65cb27e5bfe2449493a35357973253fe1e322a169fdb2ba6debbe824975c9e66b556d837a6b37b25231503a3cda0edcea0db7b2fe8d1f5743106c048f6c0d905f65212161451f8936a5f051e2ad800783e4bb590269dd5d15e3e33f7120972dc850bf63b5e7e2ab9ddc052133331b599e81ca04a036cfcfa7a798028f791aea99bafdd4e3c3ca2
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166686);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/28");

  script_cve_id(
    "CVE-2022-22241",
    "CVE-2022-22242",
    "CVE-2022-22243",
    "CVE-2022-22244",
    "CVE-2022-22245",
    "CVE-2022-22246"
  );
  script_xref(name:"JSA", value:"JSA69899");

  script_name(english:"Juniper Junos OS Multiple Vulnerabilities (JSA69899)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by multiple vulnerabilities as referenced in the
JSA69899 advisory.

  - An Improper Input Validation vulnerability in the J-Web component of Juniper Networks Junos OS may allow
    an unauthenticated attacker to access data without proper authorization. Utilizing a crafted POST request,
    deserialization may occur which could lead to unauthorized local file access or the ability to execute
    arbitrary commands. This issue affects Juniper Networks Junos OS: all versions prior to 19.1R3-S9; 19.2
    versions prior to 19.2R3-S6; 19.3 versions prior to 19.3R3-S7; 19.4 versions prior to 19.4R2-S7,
    19.4R3-S9; 20.1 versions prior to 20.1R3-S5; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to
    20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S2; 21.2 versions prior to
    21.2R3-S1; 21.3 versions prior to 21.3R2-S2, 21.3R3; 21.4 versions prior to 21.4R1-S2, 21.4R2-S1, 21.4R3;
    22.1 versions prior to 22.1R1-S1, 22.1R2. (CVE-2022-22241)

  - A Cross-site Scripting (XSS) vulnerability in the J-Web component of Juniper Networks Junos OS allows an
    unauthenticated attacker to run malicious scripts reflected off of J-Web to the victim's browser in the
    context of their session within J-Web. This issue affects Juniper Networks Junos OS all versions prior to
    19.1R3-S9; 19.2 versions prior to 19.2R3-S6; 19.3 versions prior to 19.3R3-S7; 19.4 versions prior to
    19.4R2-S7, 19.4R3-S8; 20.1 versions prior to 20.1R3-S5; 20.2 versions prior to 20.2R3-S5; 20.3 versions
    prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S4; 21.2 versions
    prior to 21.2R3-S1; 21.3 versions prior to 21.3R3; 21.4 versions prior to 21.4R2; 22.1 versions prior to
    22.1R2. (CVE-2022-22242)

  - An XPath Injection vulnerability due to Improper Input Validation in the J-Web component of Juniper
    Networks Junos OS allows an authenticated attacker to add an XPath command to the XPath stream, which may
    allow chaining to other unspecified vulnerabilities, leading to a partial loss of confidentiality. This
    issue affects Juniper Networks Junos OS: all versions prior to 19.1R3-S9; 19.2 versions prior to
    19.2R3-S6; 19.3 versions prior to 19.3R3-S7; 19.4 versions prior to 19.4R2-S7, 19.4R3-S8; 20.1 versions
    prior to 20.1R3-S5; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions
    prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S2; 21.2 versions prior to 21.2R3-S1; 21.3 versions
    prior to 21.3R2-S2, 21.3R3; 21.4 versions prior to 21.4R1-S2, 21.4R2-S1, 21.4R3; 22.1 versions prior to
    22.1R1-S1, 22.1R2. (CVE-2022-22243)

  - An XPath Injection vulnerability in the J-Web component of Juniper Networks Junos OS allows an
    unauthenticated attacker sending a crafted POST to reach the XPath channel, which may allow chaining to
    other unspecified vulnerabilities, leading to a partial loss of confidentiality. This issue affects
    Juniper Networks Junos OS: all versions prior to 19.1R3-S9; 19.2 versions prior to 19.2R3-S6; 19.3
    versions prior to 19.3R3-S7; 19.4 versions prior to 19.4R3-S9; 20.1 versions prior to 20.1R3-S5; 20.2
    versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1
    versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R3-S1; 21.3 versions prior to 21.3R3; 21.4
    versions prior to 21.4R1-S2, 21.4R2; 22.1 versions prior to 22.1R1-S1, 22.1R2. (CVE-2022-22244)

  - A Path Traversal vulnerability in the J-Web component of Juniper Networks Junos OS allows an authenticated
    attacker to upload arbitrary files to the device by bypassing validation checks built into Junos OS. The
    attacker should not be able to execute the file due to validation checks built into Junos OS. Successful
    exploitation of this vulnerability could lead to loss of filesystem integrity. This issue affects Juniper
    Networks Junos OS: all versions prior to 19.1R3-S9; 19.2 versions prior to 19.2R3-S6; 19.3 versions prior
    to 19.3R3-S7; 19.4 versions prior to 19.4R3-S9; 20.1 versions prior to 20.1R3-S5; 20.2 versions prior to
    20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to
    21.1R3-S2; 21.2 versions prior to 21.2R3-S1; 21.3 versions prior to 21.3R2-S2, 21.3R3; 21.4 versions prior
    to 21.4R1-S2, 21.4R2-S1, 21.4R3; 22.1 versions prior to 22.1R1-S1, 22.1R2. (CVE-2022-22245)

  - A PHP Local File Inclusion (LFI) vulnerability in the J-Web component of Juniper Networks Junos OS may
    allow a low-privileged authenticated attacker to execute an untrusted PHP file. By chaining this
    vulnerability with other unspecified vulnerabilities, and by circumventing existing attack requirements,
    successful exploitation could lead to a complete system compromise. This issue affects Juniper Networks
    Junos OS: all versions prior to 19.1R3-S9; 19.2 versions prior to 19.2R3-S6; 19.3 versions prior to
    19.3R3-S6; 19.4 versions prior to 19.4R2-S7, 19.4R3-S8; 20.1 versions prior to 20.1R3-S5; 20.2 versions
    prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions
    prior to 21.1R3-S2; 21.2 versions prior to 21.2R3-S1; 21.3 versions prior to 21.3R2-S2, 21.3R3; 21.4
    versions prior to 21.4R1-S2, 21.4R2-S1, 21.4R3; 22.1 versions prior to 22.1R1-S1, 22.1R2. (CVE-2022-22246)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  # https://supportportal.juniper.net/s/article/2022-10-Security-Bulletin-Junos-OS-Multiple-vulnerabilities-in-J-Web
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa3dba08");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69899");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22241");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
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
  {'min_ver':'0', 'fixed_ver':'19.1R3-S9'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R3-S6'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S7'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S9'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3-S5'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S5'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S5'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S4'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S2'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S1'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  pattern = "^set system services web-management";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as J-Web is not enabled');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
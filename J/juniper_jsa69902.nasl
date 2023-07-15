#TRUSTED 3654465c035d5a1203249a15884153f52a4263f00d68543926346522b15cc837d48a2ec420a9c7d20f886057d3a92d603fd48f354db45f6b4eb57673fa5a6ec97f30e28849f04d5160c39501452ac7a44d4344d223ec31c4cf37ce1e4153333978f51e4c777fada8930436a6cf45daf0ddfd967aab94fb2802a1c7e78262b27e3685294064532e7edcce4f3452744b64c2d954074e3a060939406991f7bb00127e54028d66a52522726baf3a8379209a49b176b0febc6c6008d5a150836ece3f9e7fe25bab5b755e261eb4af75ee47a92081f05b887a79c82bd28b358138dd80d9cf3e137b2d755d796d52e53a60ea9fd2f809a8fb748b8cc23582cf51b57199278ae18c19215e76ce5a6254e3986a4a7754d87223d56f40f58786e302bd828cd98dfdfefea29346caf2ba303ef29058ed60da58c3cceacaadfdf4a5ebf6c0473fd5cb79fbc31ce09ee2cec7d5f01044d6e1a3f1b73a6c469e73b1b5027ce88f90febd496641b660933c05c1daf11d85c38ecde83162964ee0aa20eeb7df3f8acc2c1cdbc1e8b23674d6ab53d68e4e1446442b3e41ad84642a4cdb3b9a96e2ffec3b26f1ebc5bac9752d3f464ec4ca7e8f78208b3409134795005332c766229446eb92ad5abdfcb9d22642d88b6d2af447136d370cb2e0edef7080a4f2215423f2cf0e3320f3bbee9b5f8f3af7005c8f23b8d95d8398816a798bfd91d7d3414f
#TRUST-RSA-SHA256 205e2b41fa34bc1cb30274df1361e583af1f5f5e5153a975e75aaa439b93acfab2269ed6cd8bd0fc1ffe3e2216161e84d54fd7e12b88207b77ad97048fa2a5f9be93e659898276568aa823bfe0d6f1670c59d08a71b4c9cd68460bd15b2821df0f1eb0cd7f0b0119abe1bc7c74cb4dcb916b24c88ac1827363199829bddf96feda3821d99de2195007164b9658ef0a973d28c06e9f6575432834cce59e49313c0b2a616e12eb28e53df361dc6138078c13ff26ae88466fe1765e8664cd1a122871140795e84b66b0f02afa1a15094eb440c8909dc0684ba42c14628b93dcc0a9be64d3d0d434c8c7815b39b3d4ac974ced227bcd3e41d0ef1c3027b2d9631b63b70f0e3afd0bd7a65ff6fa1ea5303bedff885f96b89a6e4fb943fe49c77cac0e756438fe5450bb36f31236680243b27923f3761fc91c7b6db7bcc9dc69971e1561582f08cef81b8896bad77efd06b86506637c6a2428125182ec973018e7953030d2670550685bc1aab09cf6ed558e61c690aedff151e643fb2087c77d6f25a8e4520722b6202b894e701a4a68a5288e08ea9042336148156a50b9e679683ca6028c3dd9a26aeeafa6755ea66f8a67abd432762492cfe8933fa6f5a889b233b70b0370f76ef759e8b2f20663f2b1b80219dc22c584d71cc10c067522bedc5c3c87b790933b52a53bfb59a1697f74d4001902597e61af52cdfc87dc2a49ca8a6d
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166319);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/28");

  script_cve_id("CVE-2022-22220");
  script_xref(name:"JSA", value:"JSA69902");
  script_xref(name:"IAVA", value:"2022-A-0421");

  script_name(english:"Juniper Junos OS Time-of-check Time-of-use (TOCTOU) Race Condition DoS (JSA69902)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a DoS vulnerability as referenced in the JSA69902
advisory. A Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability in Routing Protocol Daemon (rpd) of Juniper
Networks Junos OS, Junos OS Evolved allows a network-based unauthenticated attacker to cause a Denial of Service (DoS).

To be vulnerable to this issue a device needs to be configured with a minimal BGP flow spec configuration like in the
following example:

[protocols bgp group <group-name> family <family> flow]

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  # https://supportportal.juniper.net/s/article/2022-10-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-Due-to-a-race-condition-the-rpd-process-can-crash-upon-receipt-of-a-BGP-update-message-containing-flow-spec-route-CVE-2022-22220
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e1313eb");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69902");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22220");

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
include('junos_kb_cmd_func.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S10', 'fixed_display':'18.4R2-S10, 18.4R3-S10'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S7'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S8', 'fixed_display':'19.2R1-S8, 19.2R3-S4'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S3'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S2'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R2'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set protocols bgp group .* family .* flow"))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);



var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"protocols evpn", multiline:TRUE)
  || !preg(string:buf, pattern:"leave-sync-route-oldstyle", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'running a vulnerable configuration');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
#TRUSTED 4559fdd20fca13d6d93bc09d6a543339c28eff6a8a5078ed1803b06976db16bfd5e8f4036022c2bd39aefc15e37ce6a5af2226b300911a0e46ddb42668878ca6a02788cd9c4c6df0b794efb396275e7f70f8116bb81301c10742d92d2bb4c7f29457034499a405bd31173f07fb06174033d8b853c33a211636c26a530beb9a31543fd40ef7b3ad78ffd0e848d064c0cb9a003a53559d3c09eea55bf3625e8972bdd28b95cca54eb9b04beb424ec7be3361019bac84036c16d311ed5eaecac8afa13bec97a27df5c9de77c1738445e4e89b798044dc9e3e03a67c66ab90d3a6b64dc452061ed4b1906c02d48fe80ef5e2de45c27c9b202d3e95829761131f5d7ffd9490dc4f360c6659b255a5242b230852f2562554fc11c270e9733b5e2da20c741dafa1da6f4ffac6a4d7ba284a2bd50932a7db86dcfd950f53675ad42c53307a7be00caa70443392ea623d3d1c62b1e06cbec88a0933e4fe8a2a4adb10f74e300311628abdbdac40a77f34c142039221bedf8f956e5595ba7e98eaa58c640810e3edf7fae89932722ea236bd38b407d7f6a2978f182dc374f25de6428cd25d2f56fc434a82303d358826c9d046e826cf5fb4b41dc3f33704584db7288d46ea18fe341dfb12bbd826a280105af0b56c7eabd2534d97c47f5b0724ca422c2070cae77c7dfb92a29f3ac78375b072bf61f086966a6d3fb6c0da4ddf1bb4e96800
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130515);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2019-0067");
  script_xref(name:"JSA", value:"JSA10966");
  script_xref(name:"IAVA", value:"2019-A-0388");

  script_name(english:"Junos OS: MC-LAG DoS (JSA10966)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper Junos device is affected by a denial of service (DoS)
vulnerability on devices configured with Multi-Chassis Link Aggregation Group (MC-LAG). An unauthenticated, adjacent
attacker can exploit this by continuously sending a specially crafted IPv6 packet to repeatedly crash the system and
cause the device to stop responding.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10966");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10966.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0067");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('audit.inc');
include('junos.inc');
include('junos_kb_cmd_func.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();
fixes['16.1R'] = '16.1R6-S2';
fixes['16.2R'] = '16.2R2-S10';
fixes['17.1R'] = '17.1R3';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# If MC-LAG is not enabled, audit out.
# https://www.juniper.net/documentation/en_US/junos/topics/topic-map/mc-lag-redundancy-and-multihoming.html
override = TRUE;
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  pattern = "^set ae.* aggregated-ether-options mc-ae mc-ae-id";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as MC-LAG is not enabled');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);

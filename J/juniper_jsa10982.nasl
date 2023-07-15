#TRUSTED 7d144eec578413524b8371fd26088c2644b8b85e0d3d1506a500fae9c8d6da66faed1df9030bb15c46145677714b9de6ddbc219d210546479e0540a42b79fc0bf7a254e4c37f0f6f06aefd928b723a36bd67e29ce9c92eb43bd33cd6c7749d89863204cc26e0dcb9c990a48bc72c4fc697b8a82d0b04d05f99a1532d4c14f3e9b2eca8440cfd30f887cfde35a31748c49354f85578cecca82bcd8703f3c1fca5a731d3a3b7577ce8c88ce42ea344cab96bc502247cf3f71986df85a8f5c5b227c0325364a38697d52ed7fc05db6a0e4462cffc5f919ae27145d397f6a120bf0b8afd848cf5deafb26ec99189b0dd6a82cfd1a7799825c9246a4e08c371e265197f4207d24e108492a65e2c2029f03c2408960ea18702ac7dee8bcb6714a635232f340328b2b133b8dc32edfdd7e71b4c688cf80d280663cfd888f705bbc31c550036dbe53f3334d54878e16862ed707076e8bc78f4e0b38c5a0e8d6d7ad3da1658d2a0af516620a2b357693bca99b02d033df8ed47c3ba75271ee20a8ff20723bd3885002ea3b27e331229fcf4164ec55896f4e28cce11fb8036915e49998c36afd65d7017e68638cba7bf86e5cfb73c1022f41bb8ab65da97fea2900c8da2df30a996ec5728789b3fa52dad08ebf68dd2f31b8887682531d3a7a19bc52a8d76be3f69c5c7ea2864009d7f70e97d557d78e2ecfd4fd66059c36445aa8b741f79
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133860);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/16");

  script_cve_id("CVE-2020-1603");
  script_xref(name:"JSA", value:"JSA10982");

  script_name(english:"Junos OS: Improper handling of specific IPv6 packets (JSA10982)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper Junos device is affected by a 
denial of service vulnerability (DDOS): Specific IPv6 packets sent by clients processed by the 
Routing Engine (RE) are improperly handled. A remote unauthenticated attacker can exploit this by
sending specfic IPv6 packets that can cause a memory leak which can lead to a distributed denial
of service attack (DDOS).

Note that Nessus has not tested for this issue but has instead relied only on the application's 
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10982");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10982.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1603");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('misc_func.inc');
include('junos_kb_cmd_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

#skip this version as 16.1R1 is not vulnerable
if (ver =~ '^16.1R1')
    audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();

fixes['16.1R'] = '16.1R7-S6';
fixes['16.1X70'] = '16.1X70-D10';
fixes['16.2'] = '16.2R2-S11';
fixes['17.1'] = '17.1R2-S11';
fixes['17.2'] = '17.2R1-S9';
fixes['17.3'] = '17.3R3-S6';
fixes['17.4'] = '17.4R2-S9';
fixes['18.1'] = '18.1R3-S7';
fixes['18.2'] = '18.2R3-S2';
fixes['18.2X75'] = '18.2X75-D50';
fixes['18.3'] = '18.3R1-S6';
fixes['18.4'] = '18.4R2-S2';
fixes['19.1'] = '19.1R1-S3';
fixes['19.2'] = '19.2R1-S2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

#command found at: https://www.juniper.net/documentation/en_US/junos/topics/topic-map/ipv6-interfaces-neighbor-discovery.html
buf = junos_command_kb_item(cmd:'show interfaces terse');
if (junos_check_result(buf) && buf =~ "inet6")
{
  report = get_report(ver:ver, fix:fix);
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

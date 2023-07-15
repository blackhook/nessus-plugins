#TRUSTED b239651d1a98ea42883a40232dc23e35ebb7257c07b2031e8245bb23de7f311a5ac40d79deef0c4534e434b2b6fb95845a2285f1ed32ae3ce02f9a9d9bc6299dd4edbafca2db742a8c4999a068e45a0996b106a4dfe3a5e52c0d6667096651aad7efa84f7112fe044527384165bd48ca6e8c4a857bb45d120b4bafeb046a7a99b6f2a9917b82199d170ec4f44ab2a8c19a01de4b0c7e2fe5b4890d4e9851c68228b7d859323dd770d5482418946cd282e8015fb73d6523b8d8a1f59fab80958b0a246285d85130c029b444e78aabe1c21367c6670c91a742a52ceaa1331219530bea73172f4b36337eced8ef6cd9459a9f9a3e7514c57aeaeada63059f1e96228a56ffd1d74f53dcd46d3359c9f05cf071769f9be7b53a236089097b89b9e5c2609039ea2fa73a8776af06f00060f66c7373c10fab7fc872891c1cbdd01273f7153507f5c49226f6c7b2a05c0f8617d1692628c97fa5500c59d8f0dc881bf87b593abca7fba9845e4fcdc6b285aca56daf6bc60b9399b6f775862045cb2869801c5ddebc5a24a408e8f9b1194f98b946cac3378ebe74f6004516934e0cb382e117ad8041b1feb18403800a6ef253c19b20c25573fbf2679bb16d149936ec83e714c6683708e724f3812a7a2050636e82efd2cd2c5622e3a3639854ba35936de2d80f70971e6db29c0fd70886690a9f514ad89994e878b46eda141228163235ce
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130466);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2019-0064");
  script_xref(name:"JSA", value:"JSA10963");
  script_xref(name:"IAVA", value:"2019-A-0388");

  script_name(english:"Junos OS: flowd DoS (JSA10963)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper Junos device is affected by a denial of service (DoS)
vulnerability in the flowd process on SRX 5000 devices when 'set security zones security-zone <zone> tcp-rst' is
configured. An unauthenticated, remote attacker can send a crafted TCP packet to crash the flowd process and trigger a
new session. Repeated crashes of the flowd daemon can result in an extended DoS condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10963");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10963.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0064");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('audit.inc');
include('junos.inc');
include('junos_kb_cmd_func.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
# SRX5000 Series
if ( 'SRX5' >!< model)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['18.2'] = '18.2R3-S1';
fixes['18.4'] = '18.4R2-S1';
fixes['19.2'] = '19.2R1-S1';
fixes['19.3'] = '19.3R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# If  'set security zones security-zone <zone> tcp-rst' isn't configured, audit out.
override = TRUE;
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  pattern = "^set security zones security-zone .* tcp-rst";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as it does not appear to have a security zone with tcp-rst enabled.');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);


#TRUSTED 7c5ad024497c6e84cf3917d899e7dcdfc9d7ce7fdebfcb66158afd3ae1a84af5e11f4051a5efdbec31463f9ec36a3d9a19739ebcf4c255904758c6bcca7634084c3fbab52b04c269bbd9ae796f94f056f42d1763a5c66e26ae5432204a65c512f1b5b752e460a275988aefe9113013bfe3f70b4480c6b494a1e9da33d394ef6bd395f55a3d95475619afddaec730256f5d9483a21f8a6634bd8d5a89b3b57e84f6173bfecb59a173feb24aec346b5619330b63a2baddb1e0a883b76eb14c3929c38cf1f25ca8bb2ca4a18bd2fde57491154681c275d17efccefdeb8d7c96726c31a51f7b803565ded87acd423f0fd15484df65c4e12fd093bef68f25dfb4381059e745a6971eab6d0d8726b76c436323de28d46b9106c45fdaf075696d40b636d2a401677c030e8d7ab647cd3009bbab51ef6ac97cf5a8629889fb169cb9a6453174e02b80b3bec1eaf2e99d4b0e57fbd267703863d527ac38af71e60cf327fdf244b6b55d85ec39770fcacf66c73bd143e2b5563c62531b3a1df3a5179e72c9c73dd4f7ef1e4d350273df26e5e25db9555eb239bbc6ae25cdf486a3952d0422deffe1d89585f3300fc661dc1705b82fc3b5c21deb5e9377fd5487b554be912fe578e7b2f91126c2d9366d4e08adf9a03632816ba6b81352f4179c0c7dab8508cbaa751951e85f7c1cea004ee1be9846e0903a561fa945e722feacf92366e676
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130505);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2019-0055");
  script_xref(name:"JSA", value:"JSA10953");
  script_xref(name:"IAVA", value:"2019-A-0388");

  script_name(english:"Junos OS: SIP ALG flowd DoS (JSA10953)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper Junos device is affected by a vulnerability in the
SIP ALG packet processing service which allows an attacker to cause a Denial of Service (DoS) to the device. A remote,
unauthenticated attacker can exploit this by sending specific types of valid SIP traffic to the device to cause the
flowd process to crash and generate a core dump while processing SIP ALG traffic. Continued receipt of these SIP
packets will cause the device to stop responding.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10953");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10953.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0055");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/05");

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
# SRX Series
if ( 'SRX' >!< model)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();

# 12.3X48 versions prior to 12.3X48-D61, 12.3X48-D65 on SRX Series;
# Making this paranoid
if (report_paranoia >= 2)
  fixes['12.3X48'] = '12.3X48-D61';
fixes['15.1X49'] = '15.1X49-D130';
fixes['17.3'] = '17.3R3';
fixes['17.4'] = '17.4R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# If SIP ALG is not enabled, audit out.
override = TRUE;
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  pattern = "^set security alg sip";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as SIP ALG is not enabled');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);

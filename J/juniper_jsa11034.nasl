#TRUSTED 89937ff467ce947cd03a7fa66c786b899426b68258acaee8a52e479c3b74f03da430933b8b5250c18a6124c446f8a83e6aaed0ba5e62a83b5f6fc74549087a19f6d1641f5a6f7ff1fd0c52aa9e7c3899503b998b0810c2f5907c91ff8d880893618644438ab98ab7b04811abc46d0bd3210c6e6b5d294ba539d651e823afcb45c56cacd474e7ba691bed96de9e3007a21833a04b351acadf1d12ac3a61d2519a5dfcf59d451fe8478f7673471d68fe2a8f20f02000caa41c06f2caa6e2ef625c8f0521ab8d82b4ee718db63604f7931861e79869742b3daa98b1023caf753e09f0f2bd354add42aa5eab7da0c8dafe0d9371a04e7d6bb476411f959b2199fd6ff113ac150da0012c70b142114cdb9ac7c74c4f5bf51bccdd66ee72feab6bf97ee7a91dcdb4e1ee6970a540b237af91c9b3b941265bb666e143e571e4f359452496a4169c1036df70680255b7d9876163132332236e80b1533028cfc5312063defb9da68ca7baedc37e95aaf7c2ea04ce2fa44d90c8cc6cac5ec0003fe5bd6765b59bd7a6ad0b8314ab06339178dc5724e3d3cdb83ee52f973d64d4cbdbfa998182ce035be6bcadb19d01b560ca5d810c1cb0144bd05f226bd6c43393d5c0e7c423826e61bed8649a9009c0b2dc23770a6cb3495ac0a2832be5506416f03f26a46fcc52f4795b46809f4193e9575acdf69e8fb60dd68aef00f0be17d9b65913b0
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138839);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/13");

  script_cve_id("CVE-2020-1647");
  script_xref(name:"JSA", value:"JSA11034");

  script_name(english:"Juniper Junos SRX Double Free ICAP Redirect DoS RCE (JSA11034)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Junos OS on the remote device is affected by a double free vulnerability.
On Juniper Networks SRX Series with ICAP (Internet Content Adaptation Protocol) redirect service enabled, this double
free vulnerability can lead to a Denial of Service (DoS) or Remote Code Execution (RCE) due to processing of a specific
HTTP message. Continued processing of this specific HTTP message may result in an extended Denial of Service (DoS). The
offending HTTP message that causes this issue may originate both from the HTTP server or the client.

Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11034");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11034");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1647");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if ('SRX' >!< model)
  audit(AUDIT_HOST_NOT, 'an affected model');

fixes = make_array();

fixes['18.1'] = '18.1R3-S9';
fixes['18.2'] = '18.2R3-S3';
fixes['18.3'] = '18.3R2-S4';
fixes['18.4'] = '18.4R2-S5';
fixes['19.1'] = '19.1R2';
fixes['19.2'] = '19.2R1-S2';
fixes['19.3'] = '19.3R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  pattern = "^set services icap-redirect profile";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration1');

  pattern = "^set services icap-redirect profile ([^\s]*)";
  match = pregmatch(string:buf, pattern:pattern);
  if (empty_or_null(match) || empty_or_null(match[1]))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration2');

  prof_name = match[1];
  pattern = "^set security policies from-zone.*then permit application-services " + prof_name;
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration3');
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);

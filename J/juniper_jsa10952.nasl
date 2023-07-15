#TRUSTED 4135f48ede6cd50fea1d0d5f71ee371fd2292bb3b7acfe1159723931193790c4eb12f274af1171e605dc0c2dff15cb28e9bedbb8f1db70317bdd2eea8f46be3ab7d98bc41a76c989d1cf8abf5948018ebeddc1fbe188ee13a85238b2fc43f6f94b34745e4a02b81ecf6660c4a631795cca61461c9ebfdba458bd134406144919137b6790413e8538335266c494c7799678e00d87b439a1819205b717c95737b857c54095cd9ebc3c56afaa74444d14ff86588e53a61db3a1f6e788f41c465cae4f6a84ff9259d793e677c1c2799b988715eb97657828e9099a5dc335fd5240b855899f416d2ed98b155ed1a9e6aaa55a65e99d6c104fb41b80c58e4352bed71416e87de5ac175c4527f0a820b18a66aafeac82bb59de00634aaba99a53a75a3f0e37fec08acf050784d6907a50f8fa7bcb1c77117034859d533d742b86cb26d522ce0bb6cc57feb2864fe03fdbb004e854eb29a25aefc1398a1293c8c82e79311da657a673e2d893c422edc26c82c1218586f92d0a8631910a3b4ee3c775707fb31d0057f4e9071e977858e6da0738fa11d0463524e30e9c39183b41940055856662b44ff3ab5b4104dae7bbf16f9288685ee91bdbc16240bab3622659f5f3eaea1d9d3968dc9cc1b670a6de93d0671d3e1f273a060514c579f69ae5c45902198ea86b23bca98a9214ed846d6ac05a6ac5468708a925b64baf55ddbee9a1851c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130469);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2019-0054");
  script_xref(name:"JSA", value:"JSA10952");
  script_xref(name:"IAVA", value:"2019-A-0388");

  script_name(english:"Junos OS: app-id Signature Update MitM (JSA10952)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper Junos device is affected by a weakness in the
Application Identification (app-id) signature update client. This allows an unauthenticated, remote attacker to perform
a Man-in-the-Middle (MitM) attack which can compromise the integrity and confidentiality of the device.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10952");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10952.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0054");

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
# SRX Series
if ( 'SRX' >!< model)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['15.1X49'] = '15.1X49-D120';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# If application-identification is disabled, audit out.
# https://www.juniper.net/documentation/en_US/junos/topics/topic-map/security-application-identification-overview.html
override = TRUE;
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  pattern = "^set services application-identification no-application-identification";
  if (junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as application identification is disabled.');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);

#TRUSTED 9818b540a13bd5aebd43cc35808207401eb41487dd09a933dbce89eee26c4557f5bd13aa490abf33b92adc265972a8d2883328840bff21f34df8e09c0eb37d4eb8ed0675d24e378bfd7eedc092c65bb8382dac0177e0c1fb27d0f9dd6e1627d26902988545d43db2366db9cc33532bb7332d30d2c9165d2479644bf76c6ed4261400f176fadd1e9f796f3f5ac90f56579982cf0b64749c1a79041bffd5fa1d87d1ce796d1846e2e35950c3ed5ea940d3c8140479077433939679fcb41c338bc6640058aed252fa58ae75c9867a2f6129b164c5280377756da3580c9a7b29b8eb8a87dc27996295225413ba953f7f51e70a938214f41bab1b1f679c7714d4bb2c4ffc2e94ab8e5d0b23ae9fbd63218cafcb167c44fe7ca7c47ce7ab590a0e8264c5d796842f28981399d0a8000b58d32219055b433130ca8880385f22869f4ebe94f497f7875c0ca70957bc7e7840d11ad5c066bbd1aefadb70c5e149f793da62387bcccf0dbc0d39ee3ff5df6f0373d2c97ba3aba2bba999c8d030e56368f4d156de2fd89379a6954999155738f6cbae88663124439ec878684de4fc67d4dd775f31f751ee491a85ed79bb06b66bbbab32c0b54b909855b2f6dd0a568e3027e7f17b2cb69a3a1019461c82c852b07d10292d1def0e30faab84b3487e827b1712586b1d631c637f5ec5c46e771454ab667f161b5d86809a4db9c1155982953055
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130270);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2019-0051");
  script_xref(name:"JSA", value:"JSA10973");
  script_xref(name:"IAVA", value:"2019-A-0391");

  script_name(english:"Junos OS: SSL-Proxy DoS (JSA10973)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper Junos device is affected by a denial of service (DoS)
vulnerability in the SSL-Proxy feature on SRX devices, which fails to handle a hardware resource limitation that can be
exploited by remote SSL/TLS servers to crash the flowd daemon. Repeated crashes of the flowd daemon can result in an
extended DoS condition. An unauthenticated, remote attacker can exploit this issue, by convincing clients protected by
the SRX device to initiate a connection with a malicious server, which will cause the system to stop responding.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10973");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10973.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0051");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/25");

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
fixes['12.3X48'] = '12.3X48-D85';
fixes['15.1X49'] = '15.1X49-D180';
fixes['17.3'] = '17.3R3-S7';
fixes['17.4'] = '17.4R2-S6';
fixes['18.1'] = '18.1R3-S8';
fixes['18.2'] = '18.2R3';
fixes['18.3'] = '18.3R2';
fixes['18.4'] = '18.4R2';
fixes['19.1'] = '19.1R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# If SSL-Proxy feature is not enabled, audit out.
override = TRUE;
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  pattern = "^set services ssl proxy";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as the SSL forward proxy feature is not configured.');
}
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);

#TRUSTED 7b65712c030070ba042c0719decdee00a8d5a8711532283a9f513e3be3da79da169b73b53364383feb4902f3b3bf1e03d407ad25d991d5c20f73411ff7771f63b45e6cd88c0b6051975d53741edbc9190bd7e5849980dae689d022c2b7be62416197877b5fa85ef3c5da3dca998ffa77632fd1c8366fab6c62b98a7a06148022a77702958dd3fb07c63b84a8611f5460db78021ac198e33ac7f2ea70f98c09d598467e4c10761423b6816851786e0beafd865e8659997c21725bc485a70ad3e140c1c07d6ea8048964d3cc857cb96872edf68c021ecd898ca219085d46dca362d1e9fdccf0a05a088055b9fd5b9ff21e00923a19d7c74ff19d8e71ad56d27757c69b4e6f456d8186d8c15358ca160c7aee121536c2791fdd93a288f6b961a387d36dbbeb1001eb69c1529c775450ddf678ea073ab72cc1b1fc1344d1be6706069c1cbad84c284f98949c6b389567d49560e157372a9646f5c86bfd826f60c558b7e22b7e321169ad6786e4e0bb8ef92c28c07ee8bab5c2f4ab3d7fda5906015de1c0ecde36f43f45d525941bff928f1af258193b9c87abb438372397dcd7f9a61e1538596c5686d93e3ab5e3baafbe03a7586cc7f26a85bb225614d4f6140773bbcf7904ab11c5d65145e4f23a6a8ff8b58281d93b3564127e045396a0c0a61627b5f318e5f5db79af46290ee3b672d284b2e574e9cacba0fd56237888c24e1a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140586);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-1645");
  script_xref(name:"JSA", value:"JSA11028");
  script_xref(name:"IAVA", value:"2020-A-0320-S");

  script_name(english:"Juniper Junos DNS filtering JSA11028");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to the self reported version of Junos OS on the remote device is vulnerable to improper input validation.
When DNS filtering is enabled on Juniper Networks Junos MX Series with one of the following cards MS-PIC, MS-MIC or
MS-MPC, an incoming stream of packets processed by the Multiservices PIC Management Daemon (mspmand) process,
responsible for managing 'URL Filtering service', may crash, causing the Services PIC to restart. While the Services
PIC is restarting, all PIC services including DNS filtering service (DNS sink holing) will be bypassed until the
Services PIC completes its boot process.

Nessus has not tested for this issue but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11028");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11028");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1645");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

# This issue does not affect Juniper Networks Junos OS releases prior to 17.3R2.
vuln_ranges = [
  {'min_ver':'17.3R2',   'fixed_ver':'17.3R3-S8'},
  {'min_ver':'18.3R2',   'fixed_ver':'18.3R2-S4'},
  {'min_ver':'18.3R3',   'fixed_ver':'18.3R3-S1'},
  {'min_ver':'18.4',   'fixed_ver':'18.4R2-S5'},
  {'min_ver':'19.1',   'fixed_ver':'19.1R2-S2'},
  {'min_ver':'19.2',   'fixed_ver':'19.2R1-S5'},
  {'min_ver':'19.3',   'fixed_ver':'19.3R2-S3'},
  {'min_ver':'19.4',   'fixed_ver':'19.4R1-S3'}
];

override = TRUE;
buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
  {
    override = FALSE;
    pattern_w = '^set web-filter-profile ';
    pattern_d = '^set dns-filter-template ';

    if (!junos_check_config(buf:buf, pattern:pattern_w) &&
        !junos_check_config(buf:buf, pattern:pattern_d))
      audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
  }

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (!isnull(fix))
{
  junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
}

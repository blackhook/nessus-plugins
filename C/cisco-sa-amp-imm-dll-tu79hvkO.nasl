#TRUSTED 342ae03c9b409d2d1d31c4d493879c28a26881aa48968d436012b6e272f57887d7853728ee30d9a567b4edd8a6110adfcffc0d4620851043fa2c51b4a820f06b4634c2f9cb164087c6559409f0466c14c0dbd7f32f567c21a3e32e5dff11056f8c6bf3a9e8425f54ff7ae9d8f0d54f7a2895c14a4836a663f370cf5a62e9e88185ac385bbcbdcd494aa5c9d3d1439576b24244a2c70e140fd5738b1995946b44a8325353da704c525338954a98b49ab93f2cf4bb64282ecf8a0d6b957c1f2b1ac8f91242dbfaf963568c6daf87d912039d2cd8aae787e1f0f599f353136fc994c6a56ecac2e3cfe7af22c29e3633f522ad80f85e825e2f6b8607abc8ea61c6aa44990a47b8e99d5f4c1b7e3495352e0732721b321e6ad5f8f2f4870ac050cdfe26b65731a1dff777b7b8b30e0cb815f60e2369098cdfe1d356eb07316134592d2edac2bd0c923552f418233a2a545df067d9c2dcb02f347c39b18af496f4938859f846c8ebc7f6a3074b7c05247771a2deee633a195f7ed0997d837d9796353edc0d098f8699761b37d49b61c3947ca9adae9fde10714277465942cf900048eaf080adb2778e7cda34a08c34b87167bc54cd850faeab8cdfbb378f7e7427e83923561828ab1b767862139ccd6eac247f55498621b462cf01693ca5c615e8a6e680158fd901bc87f6c840227a4c002ff177c3c02948fb289f94e8d9478c425557
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148646);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/20");

  script_cve_id("CVE-2021-1386");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw77090");
  script_xref(name:"CISCO-SA", value:"cisco-sa-amp-imm-dll-tu79hvkO");
  script_xref(name:"IAVA", value:"2021-A-0164");

  script_name(english:"Cisco ClamAV for Windows DLL Hijacking (cisco-sa-amp-imm-dll-tu79hvkO)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, ClamAV for Windows is affected by a vulnerability in the dynamic link library
(DLL) loading mechanism due to insufficient validation of directory search paths at run time. An authenticated, local
attacker can exploit this, by placing a malicious DLL file on an affected system, in order to execute arbitrary code
with SYSTEM privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-amp-imm-dll-tu79hvkO
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85e07c24");
  # https://blog.clamav.net/2021/04/clamav-01032-security-patch-release.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b00bc1d4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw77090");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw77090");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1386");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(427);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:clamav:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:clam_antivirus");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("clamav_detect.nasl", "os_fingerprint.nasl", "clamav_installed.nbin");
  script_require_keys("installed_sw/ClamAV");

  exit(0);
}

include('vcf.inc');

var os = get_kb_item('Host/OS');
if ('windows' >!< tolower(os) && empty_or_null(get_kb_item('SMB/Registry/Enumerated')))
  audit(AUDIT_HOST_NOT, 'Windows');

var app_info = vcf::combined_get_app_info(app:'ClamAV');

var version = tolower(app_info['version']);
var port    = app_info['port'];

if (
  version =~ "^0\.(\d|\d\d)($|[^0-9])"
  ||
  version =~ "^0\.10[012]($|[^0-9])"
  ||
  version =~ "^0\.103(\.[01]|-?beta[01]|-?rc[01])($|[^0-9])"
)
{
  security_report_v4(
    port:port,
    severity:SECURITY_HOLE,
    extra:
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 0.103.2' +
      '\n  Bug ID            : CSCvw77090' +
      '\n'
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "ClamAV", version);

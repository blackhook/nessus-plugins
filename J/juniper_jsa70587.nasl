#TRUSTED 60ef02832d2fb9e29d0a3750e1ac54e9da4bf427d04104b212fb3ecdae1ea1f67afbe5ade2ee96d2dd3a5f1fc793a84a1e2fb698b6fa1f6f15476b7594c854975d90eecd35643fe24d60fe7cb17a95f4a9186a5a696c50802bc4faed4565f342b7192046cc1ea2cec258309c00bece86aa3ed153e8e27e108de9193ee27858b5373e1f6f195d2485a15c5baa9600a02f27b76cba46b5587ea3413cb6c4097cfbcafceeaba8793f77fe814ccc23ca96aa61379493e282d51f80e1fc114d9077936d0f069b6c9111f4843788955c515755b7aa8b66b2622c0fcf7ef6e447b30c1e044f3e1cad54f51786fd3adcd86fb0feeaba6006e564af40178acb0aa48b25a6bfad8cb3bc544c191045a1bfb3514e9e51e3bb70b852bedc80594dbbb54b7535e6901856d917ef1e80c20b6ccb204492680e1f8eefde27ea6e787ed1c8c2edfbc6f10d1be37741e1b5743c61ae44591c0554ad0d78c8c1ca7166093167a504c0c10513e408424c3212514c214637271bcd44de4963d4f15e5568b646dfe7019d12a2cda2f0d49c92636a9beadf31645cc709e719af35848a4fdcbdd09316d7527c1dc83d1256e7a99b0ce01ab6ed8e7132108f45f868f9ad58a086c704ac69b32ed06069cea65cfa68d0ca6139789aeff54f3e1b8413ec8a92d4f644662b194a0a2f496b5c45958104c6bf88cf9d978526009fa0f9d50693d84fe73d9d8a7c08
#TRUST-RSA-SHA256 a3b52c03493a62abcedf5ac189cd0c8865534a6af537525d0a379b269e8d23b60526dd158dd5c4492934acdde93e336ef4a7683fd801d30b2a88bbd552e87b90bd03768b113125266d0a31409995c7cf76a6bafe8fa53e8f86c18221358b638920a397134264a802966da9e493abaea8ddb3e759e61e1c71524cbb07ab2efe39d0d8c0c4f662eba360d82f601316fe98b08baa60638eece3e4c2b665d5f807c3c9eab53f6665c79b76e429b7c8d1a4052ea4b4a41d029799f7eaab7e6cb83c0a9dce2b68f05a49b7dc03c4948c9248162493c9cc600ae5c6ee2504b2bbfa5672f81dadf3644f5032afdd953e4f1346ac55a1abaafad9ccb9a4a59261c427e6074df450cb0b8db00198a2ad7dc01ee3b2dc6a94401550615c9af959c6e81290fc8dca791d954018e2174ef8a769a9e862b90a5e2f579e75bc3798960913fff1f7a92e2830b923f7d067bffe1668bc0fa6895d5c6377bf2a9cccafe0a93fd9b49970f1970ed55cb8e6c4e40575a496731659f143903226468da12488794e414d17078ffe3b38bda26149430a327d2260d04cfaa00b4440054ef9cf95fca932ad778abdde25ab94274ad2330402542802519bba11f2b281477f53b3999bccff68799946f22004b764631285627fc7139e2008a5a450893fa2160e6e5a6b60b5669757bb026463b0495535472a25e775df9e8060cb56382bd024bec068169c59f071
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174741);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

  script_cve_id("CVE-2023-28962", "CVE-2023-28963");
  script_xref(name:"JSA", value:"JSA70587");
  script_xref(name:"IAVA", value:"2023-A-0201");

  script_name(english:"Juniper Junos OS Multiple Vulnerabilities (JSA70587)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by multiple vulnerabilities as referenced in the
JSA70587 advisory.

  - An Improper Authentication vulnerability in upload-file.php, used by the J-Web component of Juniper
    Networks Junos OS allows an unauthenticated, network-based attacker to upload arbitrary files to temporary
    folders on the device. (CVE-2023-28962)

  - An Improper Authentication vulnerability in cert-mgmt.php, used by the J-Web component of Juniper Networks
    Junos OS allows an unauthenticated, network-based attacker to read arbitrary files from temporary folders
    on the device. (CVE-2023-28963)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  # https://supportportal.juniper.net/s/article/2023-04-Security-Bulletin-Junos-OS-Multiple-vulnerabilities-in-J-Web
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0d623ff");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA70587");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28962");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0',      'fixed_ver':'19.4R3-S11'},
  {'min_ver':'20.1R1', 'fixed_ver':'20.2R3-S7'},  # No fixed version for 20.1R1 and later
  {'min_ver':'20.3R1', 'fixed_ver':'20.4R3-S6'},  # No fixed version for 20.3R1 and later
  {'min_ver':'21.1R1', 'fixed_ver':'21.2R3-S4'},  # No fixed version for 21.1R1 and later
  {'min_ver':'21.3',   'fixed_ver':'21.3R3-S3'},
  {'min_ver':'21.4',   'fixed_ver':'21.4R3-S3'},
  {'min_ver':'22.1',   'fixed_ver':'22.1R3-S1'},
  {'min_ver':'22.2',   'fixed_ver':'22.2R2-S1', 'fixed_display':'22.2R2-S1, 22.2R3'},
  {'min_ver':'22.3',   'fixed_ver':'22.3R1-S2', 'fixed_display':'22.3R1-S2, 22.3R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  var pattern = "^set system services web-management http(s)?";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as J-Web is not enabled');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);

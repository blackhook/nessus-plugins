#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135292);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2019-17349", "CVE-2019-17350");
  script_xref(name:"IAVB", value:"2019-B-0079-S");

  script_name(english:"Xen Project Denial of Service (XSA-295)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor installed on the remote host is affected by multiple
denial of service (DoS) vulnerabilities :

  - A denial of service (DoS) vulnerability exists in the LoadExcl and StoreExcl operations due to a possible
    infinite loop. An unauthenticated, local attacker can exploit this issue, by accessing a memory region
    shared with the hypervisor while the hypervisor is performing an atomic operation on the same region, to
    cause the system to stop responding. (CVE-2019-17349)

  - A denial of service (DoS) vulnerability exists in the compare-and-exchange operation due to a possible
    infinite loop. An unauthenticated, local attacker can exploit this issue, by accessing a memory region
    shared with the hypervisor while the hypervisor is performing an atomic operation on the same region, to
    cause the system to stop responding. (CVE-2019-17350)

Only Arm processors are affected by these vulnerabilities. x86 processors are not vulnerable.

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-295.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch or workaround according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17349");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("xen_server_detect.nbin");
  script_require_keys("installed_sw/Xen Hypervisor", "Settings/ParanoidReport");

  exit(0);
}

include('install_func.inc');

app_name = 'Xen Hypervisor';
install  = get_single_install(app_name:app_name);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

version         = install['version'];
display_version = install['display_version'];
path            = install['path'];
managed_status  = install['Managed status'];
changeset       = install['Changeset'];

if (!empty_or_null(changeset))
  display_version += ' (changeset ' + changeset + ')';

# Installations that are vendor-managed are handled by OS-specific local package checks
if (managed_status == 'managed')
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, display_version, path);

fixes['4.8']['fixed_ver']           = '4.8.5';
fixes['4.8']['fixed_ver_display']   = '4.8.5 (changeset d4d3ab3)';
fixes['4.8']['affected_ver_regex']  = '^4\\.8\\.';
fixes['4.8']['affected_changesets'] = make_list("d87211e", "a9acbcf",
  "514de95", "48ab64f", "181ed91", "c3fdb25", "7feb3cc", "343c611",
  "257048f", "491e033", "3683ec2", "a172d06", "52092fc", "e0d6cde",
  "cc1c9e3", "f6a4af3", "ece24c0", "175a698", "48f5cf7", "9eb6247",
  "31cbd18", "fcf002d", "ecbf88a", "d929136", "8099c04", "752fb21",
  "a95a103", "3dcb199", "55da36f", "160f050", "194b7a2", "a556287",
  "2032f86", "e9d860f", "a1f8fe0", "5bc841c", "4539dbc", "dcd6efd",
  "88fb22b", "1c4ab1e", "40ad83f", "51c3b69", "44aba8b", "067ec7d",
  "f51d8e5", "b9b0c46", "908e768");

fixes['4.9']['fixed_ver']           = '4.9.4';
fixes['4.9']['fixed_ver_display']   = '4.9.4 (changeset b9013d7)';
fixes['4.9']['affected_ver_regex']  = '^4\\.9\\.';
fixes['4.9']['affected_changesets'] = make_list("bc8e5ec", "34907f5",
  "e70bf7e", "fa0b891", "3a8177c", "04ec835", "8d63ec4", "1ff6b4d",
  "f092d86", "e4b534f", "87c49fe", "19becb8", "43775c0", "f6b0f33",
  "a17e75c", "67530e7", "f804549", "84f81a8", "56aa239", "105db42",
  "d9da3ea", "ac90240", "3db28b0", "9b6f1c0", "0c4bbad", "917d8d3",
  "3384ea4", "352421f", "04e9dcb", "1612f15", "f952b1d", "63d9330",
  "f72414a", "ac3a5f8", "1ae6b8e", "1dd3dcc", "7390fa1", "7e78dc4",
  "8fdfb1e", "55d36e2", "045f37c", "dd7e637", "7a40b5b", "f5acf97");

fixes['4.10']['fixed_ver']           = '4.10.4';
fixes['4.10']['fixed_ver_display']   = '4.10.4-pre (changeset f77cedc)';
fixes['4.10']['affected_ver_regex']  = '^4\\.10\\.';
fixes['4.10']['affected_changesets'] = make_list("7d51230", "6197b85",
  "71de676", "3f9140b", "7236d3c", "c18015e", "2869167", "fc1f821",
  "0976945", "c69ae56", "b8036fe", "89ac7f1", "8ae42e9", "9fa3da6",
  "7484d02", "21441ed", "1bbbfc0", "3f10c53", "702c914", "52220b5",
  "c11933b", "adf037b", "2b6ec0c", "d93becc", "357238b", "9c04e56",
  "2518d92", "69d7bed", "af62f4b", "446155d", "f947752", "5a5b128",
  "3c89988", "ac516e8", "94b82d8", "617a1e7", "d5e3494", "2cdf1b6",
  "5cfbc0f", "c1c95c4", "48bd906", "6556cce", "f6cc822", "ff09596",
  "2abefc3", "ab261f5", "71f4a76", "b32dde3", "0771bb6", "4852a15",
  "0fe82c1", "8f0b53c", "aa6978c", "923d4e8", "7ddfc2a", "f725721",
  "7dfea78", "f0c5805", "3f5490d", "d06f561", "92fc0b6", "b8071f3",
  "5200791", "3b0eebb", "5a81de4", "b2bbd34", "7842419", "9f663d2",
  "d176cd6", "a595111", "aae0d18", "631b902", "f6f1e94", "b450b20",
  "dfc7e3c", "382e4a6", "edbc9b0", "edb80d2");

fixes['4.11']['fixed_ver']           = '4.11.2';
fixes['4.11']['fixed_ver_display']   = '4.11.2-pre (changeset f459e53)';
fixes['4.11']['affected_ver_regex']  = '^4\\.11\\.';
fixes['4.11']['affected_changesets'] = make_list("f990f2a", "af90ec8",
  "8fd10a6", "38492ce", "dc556f4", "08400a7", "b415a99", "37db5e5",
  "3c3490f", "521b9f5", "e9f7dfa", "632e875", "5833f3f", "4fc7dd9",
  "6ce62fa", "2a0fda3", "8f63421", "ca73ac8", "b7ab29d", "33a9494",
  "6c33308", "f9233b7", "2effc2f", "c143106", "9d89d2c", "10a7329",
  "4f2d189", "f06cc4f", "ba75e0d", "18af067", "ec821f1", "59ae170",
  "45342cd", "8266ed6", "50c3823", "edbe121", "5b97821", "989a2ec",
  "b55ff4c", "4b72470", "5c6be59", "0ab95a9", "d85748b", "a6870a9",
  "9f4a0af", "3859ed9", "6afaac2", "a6e0749", "bd03b27", "b09886e",
  "bac4405", "0d8e6f7", "9be6613", "f5cc6e1", "3b062f5", "0825fbd",
  "bdb0630", "eb8acba", "0ebfc81", "e983e8a", "348922b", "718a8d2",
  "fc46e15", "4db8fdd", "c74683a", "793d669", "1b0e77d", "dd32dab",
  "03afae6", "aea41c3", "935a4ad", "833788f", "b77bf91", "cf99010",
  "0c0f0ab", "e984846", "4f9ab5f", "c567b05", "6c197f9", "7bbd3a5",
  "92227e2", "4835974", "be58f86", "4298abd", "4f785ea", "1028304",
  "87f51bf", "dd492b8", "e2e3a1d", "850ca94", "514dccd", "e202feb",
  "1986728", "2cd833d", "de09411", "dd914e4", "63d7113", "af25f52",
  "91f2ad7", "0b2be0b", "7d1bd98", "d8b2418", "bf608fd");

fixes['4.12']['fixed_ver']           = '4.12.1';
fixes['4.12']['fixed_ver_display']   = '4.12.1-pre (changeset f41dbf3)';
fixes['4.12']['affected_ver_regex']  = '^4\\.12\\.';
fixes['4.12']['affected_changesets'] = make_list("f8c866a", "497f924",
  "0fdad3c", "28d636d", "6fabde3", "ee4fc79", "9d78383", "4f13fc2",
  "99934ee", "b44db0b", "a18450c", "1625ff3", "1cc4541", "af3c381",
  "ac839e9", "427a8ba", "9676271", "c6ac10c", "a324e9c", "b89fe9f",
  "1e6ab8e", "69325e7", "136d10f", "86a2e13", "33f128d", "0f4974e",
  "d0d1dfb", "b02bca1", "0dcd945", "b4f291b", "c59579d", "4ed6c8b",
  "fa9d5b8", "8457c15", "0bd5e03", "8e18dca", "9d2a312", "11ffc5a",
  "b8ed146", "714207b", "45d570e", "0a317c5", "fe1ba9d", "6d8f5e3",
  "944b400", "143712d", "fd2a34c", "e25d133", "7cf6fbc", "7f53be2",
  "eb90521", "c75d5fe", "e3a1ebe", "70d613d", "8593e79", "a6c708d",
  "36f0463", "c4b1a75", "18f6fb9");

fix = NULL;
foreach ver_branch (keys(fixes))
{
  if (version =~ fixes[ver_branch]['affected_ver_regex'])
  {
    ret = ver_compare(ver:version, fix:fixes[ver_branch]['fixed_ver']);
    if (ret < 0)
      fix = fixes[ver_branch]['fixed_ver_display'];
    else if (ret == 0)
    {
      if (empty_or_null(changeset))
        fix = fixes[ver_branch]['fixed_ver_display'];
      else
        foreach affected_changeset (fixes[ver_branch]['affected_changesets'])
          if (changeset == affected_changeset)
            fix = fixes[ver_branch]['fixed_ver_display'];
    }
  }
}

if (empty_or_null(fix))
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, display_version, path);

items  = make_array(
  'Installed version', display_version,
  'Fixed version', fix,
  'Path', path
);

order  = make_list('Path', 'Installed version', 'Fixed version');
report = report_items_str(report_items:items, ordered_fields:order) + '\n';

security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);

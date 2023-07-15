#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(132391);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/10");

  script_cve_id("CVE-2019-19577");
  script_xref(name:"IAVB", value:"2019-B-0091-S");

  script_name(english:"Xen Project Dynamic Height Handling Elevation of Privilege Vulnerability (XSA-311)");
  script_summary(english:"Checks 'xl info' output for the Xen hypervisor version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor installed on
the remote host is affected by a denial of service vulnerability or possibly an 
elevation of privilege vulnerability by triggering data-structure access during
pagetable-height updates. An unauthenticated, local attacker can exploit this 
issue, by causing Xen to access data structures while they are being modified, 
causing Xen to crash which cause a devial of service. Privilege escalation is 
thought to be very difficult but cannot be ruled out.

Note that Nessus has checked the changeset versions based on the xen.git change
log. Nessus did not check guest hardware configurations or if patches were
applied manually to the source code before a recompile and reinstall.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-311.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/gitweb/?p=xen.git;a=summary");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19577");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("xen_server_detect.nbin");
  script_require_keys("installed_sw/Xen Hypervisor", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

app_name = "Xen Hypervisor";
install  = get_single_install(app_name:app_name);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

version         = install['version'];
display_version = install['display_version'];
path            = install['path'];
managed_status  = install['Managed status'];
changeset       = install['Changeset'];

if (!empty_or_null(changeset))
  display_version += " (changeset " + changeset + ")";

# Installations that are vendor-managed are handled by OS-specific local package checks
if (managed_status == "managed")
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, display_version, path);

fixes['4.8']['fixed_ver']           = '4.8.5';
fixes['4.8']['fixed_ver_display']   = '4.8.5 (changeset 8db8553)';
fixes['4.8']['affected_ver_regex']  = '^4\\.8\\.';
fixes['4.8']['affected_changesets'] = make_list("e60c718", "d46f8e0",
  "3430c46", "bafcd7f", "76dad2e", "714a65a", "d1d3431", "a260e93", 
  "ec6c25e", "1486caf", "4c666a7", "a70ba89", "6082eac", "fb93a9b", 
  "80e67e4", "dc62982", "aca2511", "17c3324", "4ffb12e", "929ec99", 
  "ae9ec06", "6c4efc1", "2867c7e", "611ca5b", "12ac129", "f1bf612", 
  "422d637", "6699295", "10105fa", "bf78103", "219b64d", "f03e1b7", 
  "048bbe8", "151406a", "d02aeba", "960670a", "4ed28df", "c67210f", 
  "d4d3ab3", "d87211e", "a9acbcf", "514de95", "48ab64f", "181ed91", 
  "c3fdb25", "7feb3cc", "343c611", "257048f", "491e033", "3683ec2", 
  "a172d06", "52092fc", "e0d6cde", "cc1c9e3", "f6a4af3", "ece24c0", 
  "175a698", "48f5cf7", "9eb6247", "31cbd18", "fcf002d", "ecbf88a", 
  "d929136", "8099c04", "752fb21", "a95a103", "3dcb199", "55da36f", 
  "160f050", "194b7a2", "a556287", "2032f86", "e9d860f", "a1f8fe0", 
  "5bc841c", "4539dbc", "dcd6efd", "88fb22b", "1c4ab1e", "40ad83f", 
  "51c3b69", "44aba8b", "067ec7d", "f51d8e5", "b9b0c46", "908e768");

fixes['4.9']['fixed_ver']           = '4.9.4';
fixes['4.9']['fixed_ver_display']   = '4.9.4 (changeset 43ab30b)';
fixes['4.9']['affected_ver_regex']  = '^4\\.9\\.';
fixes['4.9']['affected_changesets'] = make_list("55bd90d", "173e805",
  "248f22e", "ec229c2", "e879bfe", "ce126c9", "4b69427", "8d1ee9f", 
  "e60b3a9", "25f5530", "49db55f", "fa34ed5", "704f7ec", "a930a74", 
  "8c52ee2", "2e15a19", "70639ac", "c3b479d", "e349eae", "632fb4e", 
  "4608c6d", "7daacca", "859e48e", "5be2dd0", "b0147bd", "cadd66a", 
  "d3c4b60", "d59f5c4", "44303c6", "79538ba", "80c3157", "73f1a55", 
  "bc20fb1", "754a531", "7b032c2", "ff4fdf0", "8d2a688", "b9013d7", 
  "bc8e5ec", "34907f5", "e70bf7e", "fa0b891", "3a8177c", "04ec835", 
  "8d63ec4", "1ff6b4d", "f092d86", "e4b534f", "87c49fe", "19becb8", 
  "43775c0", "f6b0f33", "a17e75c", "67530e7", "f804549", "84f81a8", 
  "56aa239", "105db42", "d9da3ea", "ac90240", "3db28b0", "9b6f1c0", 
  "0c4bbad", "917d8d3", "3384ea4", "352421f", "04e9dcb", "1612f15", 
  "f952b1d", "63d9330", "f72414a", "ac3a5f8", "1ae6b8e", "1dd3dcc", 
  "7390fa1", "7e78dc4", "8fdfb1e", "55d36e2", "045f37c", "dd7e637", 
  "7a40b5b", "f5acf97");

fixes['4.10']['fixed_ver']           = '4.10.4';
fixes['4.10']['fixed_ver_display']   = '4.10.4 (changeset 6cb1cb9)';
fixes['4.10']['affected_ver_regex']  = '^4\\.10\\.';
fixes['4.10']['affected_changesets'] = make_list("ba2776a", "9d143e8",
  "fe8dab3", "07e546e", "fefa5f9", "c9f9ff7", "406d40d", "e489955", 
  "37139f1", "fde09cb", "804ba02", "e8c3971", "a8c4293", "aa40452", 
  "1da3dab", "e5632c4", "902e72d", "6a14610", "ea815b2", "13ad331", 
  "61b75d9", "e70e7bf", "e966e2e", "dfa16a1", "a71e199", "c98be9e", 
  "a548e10", "d3c0e84", "53b1572", "7203f9a", "6d1659d", "a782173", 
  "24e90db", "0824bc6", "e6f3135", "3131bf9");

fixes['4.11']['fixed_ver']           = '4.11.4';
fixes['4.11']['fixed_ver_display']   = '4.11.4-pre (changeset 005c9b8)';
fixes['4.11']['affected_ver_regex']  = '^4\\.11\\.';
fixes['4.11']['affected_changesets'] = make_list("1432cd5", "608be81",
  "d81c711", "3d2cc67", "d4a67be", "b8a8278", "06555fd");

fixes['4.12']['fixed_ver']           = '4.12.2';
fixes['4.12']['fixed_ver_display']   = '4.12.2-pre (changeset 93285e9)';
fixes['4.12']['affected_ver_regex']  = '^4\\.12\\.';
fixes['4.12']['affected_changesets'] = make_list("1363b37", "5701907",
  "f84bcfe", "5eaba24", "268e5f6", "0e3fd5d", "212b850", "2590905", 
  "4a0187b", "cfc7ff1", "54e3018", "1e8932f", "3488f26", "08473cf", 
  "acaf498", "40aaf77", "6ef9471", "dde68d8", "7275095", "3f224c9", 
  "1f6bbde", "99bc12e", "0a69b62", "e10c1fb", "e3ea01d", "c5a0891", 
  "1f86e9a", "ee55d9e", "b971da6", "28f34ab", "2caa419", "26d307a", 
  "6b88ada", "4e893a4", "3236f62", "c88640c", "a00325a", "6a66c54", 
  "0b22b83", "f0b9b67", "a387799", "1cb2d60", "875879a", "a008435", 
  "3b448cb", "1d64dc7", "d1a06c9", "1a69ef0", "18f988a", "88d4e37", 
  "36d2ecb", "ee37d67", "ece1cb0", "f4a82a3", "cf47a0e", "3334cb1", 
  "08fde90", "16f03e0", "58668f1", "0138da1", "12a1ff9", "a457425", 
  "7f10403", "b29848b", "278e46a", "7412e27", "58d59b9", "16bc9c0", 
  "694fa9c", "df67757", "bbcd6c5", "7575728", "db91ac4", "5698505", 
  "28c209e", "1b1295e", "94ff3cf", "3918f99", "81a0e12", "113282b", 
  "828e277", "f5af2b9", "09513ab", "3dc7b91", "3d83e00", "26b8dd7", 
  "5572ba9", "bb4c1a8", "81feea0", "9f74689", "5f1c9e4", "4b5cc95", 
  "ab1e6a7", "801acf8", "97b4698", "e28f7d6", "4fe70a1", "c288534", 
  "2a8209f", "bc87a2d", "8fbf991", "8382d02", "e142459", "0d210c0", 
  "89de994", "9187046", "634a4d3", "b6ee060", "61770e7", "599d6d2", 
  "9d73672", "e6ccef1", "2b84ade", "d2ca39f", "04a2fe9", "3c10d06", 
  "4e145fd", "07ec556", "847fc70", "5ea346e", "d42fb06", "32443f6", 
  "a5fc553", "b465705", "d04466f", "be2cd69", "50b9123", "8b129ba", "b527557");

fixes['4.13']['fixed_ver']           = '4.13.0';
fixes['4.13']['fixed_ver_display']   = '4.13.0-rc (changeset 47ec91f)';
fixes['4.13']['affected_ver_regex']  = '^4\\.13\\.';
fixes['4.13']['affected_changesets'] = make_list("3e1b787", "776f604",
  "cc8ac8d", "0ee7151", "f919dca", "d8538f7", "fd31193", "b0f0bbc", 
  "c6c74e3", "b789dd9", "fd9bfab", "8ba4cd9", "c1299c1", "d7abfd2", 
  "ea6a2c4", "78e7c2e", "8ba357f", "7a0e35f", "b9d5e03", "308d78b", 
  "eb6b000", "d4d4c87", "1d758bc", "e2585f8", "943c74b", "81ecb38", 
  "5655ce8", "56348df", "9a400d1", "72580a8", "195b79a", "34c1172", 
  "5530782", "3f1a53b", "4859911", "ba2ab00", "8c79c12", "77beba7", 
  "8f48634", "c568b11", "183f354", "ca4cd36", "d7cd999", "df7a193", 
  "83ac5ab", "a7b88f0", "9678167", "7059afb", "534f9e2", "a0bfdf6", 
  "0d2791b", "bad237d", "0273d8e", "f710b76", "dde3135", "3afbd23", 
  "e28eed5", "5a870b0", "f3e4fb5", "66b9765", "31c16a8", "5f7e950", 
  "e7c3202", "4abbac1", "b92a286", "65d1049", "f06d11d", "a72c508", 
  "f43afb0", "7b4c3d0", "09242da", "85e1424", "c67c43c", "8c43308", 
  "070e8ce", "0cafb89", "59e89cd", "6dacdcd", "d13dfb0", "8f1d6c0", 
  "aaef3d9", "3683290", "cda8f7e", "0c2a550", "0aaad75", "ad59145", 
  "dedcb10", "6de848f", "70fcd1e", "a458d3b", "2e2356c", "f9e10a9", 
  "f11fda9", "7afbbca", "6378a4c", "ba165e7", "92f91d2", "efee8ba", 
  "df12595", "adaecef", "354b0f2", "32e1956", "38533d9", "0ae2491", 
  "dfdb006", "ae2f94c", "abb234b", "5751861", "0f45bbb", "ed13221", 
  "7e4404f", "3ed885a", "61b6835", "a7b81b0", "6eeef7e", "319f9a0", 
  "31b4f4a", "6e8e163", "88aaf40", "c40b33d", "3c15a2d", "2f12624", 
  "d28fe10", "18b0ab6", "ff0b9a5", "2aab06d", "0121588", "1b6fa63", 
  "bf656e0", "3165ffe", "93021cb", "0bf9f8d", "ece1d5c", "b362c51", 
  "2d6f36d", "8a74707", "f51d4a1", "1a3b393", "cbe572d", "368375d", 
  "2a474dc", "7d2655f", "07149d9", "1666939", "dfcccc6", "4945041", 
  "86cf0ed", "dc2aaaf", "09348b0", "ecec150", "0e606c1", "7b1e233", 
  "64b5d83", "9633929", "333d741", "ad011ad", "95596f6", "5f135a6", 
  "af5c475", "5dedc18", "67c82f4", "a9af7cd", "2541fcc", "3f21bd4", 
  "c399983", "4f05a0c", "818927e", "3f82eb9", "7eee9c1", "529a76f", 
  "9257c21", "b7fab13", "8dea470", "a7ecdf8", "8d4f1b8", "08e2059", 
  "8dba9a8", "228a025", "59d03d2", "6da80b2", "00fc900", "4c555ec", 
  "55ab292", "e370582", "951ab40", "518c935");



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
      if (empty_or_null(changeset) || empty_or_null(fixes[ver_branch]['affected_changesets']))
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
  "Installed version", display_version,
  "Fixed version", fix,
  "Path", path
);

order  = make_list("Path", "Installed version", "Fixed version");
report = report_items_str(report_items:items, ordered_fields:order) + '\n';

security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);

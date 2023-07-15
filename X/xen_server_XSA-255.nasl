#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107098);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2018-7541");
  script_bugtraq_id(103177);

  script_name(english:"Xen gnttab_map_frame() Function Missing Mapping Check Upgrade Guest-to-host DoS (XSA-255)");
  script_summary(english:"Checks 'xl info' output for the Xen hypervisor version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor
installed on the remote host is affected by a denial of service
vulnerability.

Note that Nessus has checked the changeset versions based on the
xen.git change log. Nessus did not check guest hardware configurations
or if patches were applied manually to the source code before a
recompile and reinstall.");
  script_set_attribute(attribute:"see_also", value:"http://xenbits.xen.org/xsa/advisory-255.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/gitweb/?p=xen.git;a=summary");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7541");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

fixes['4.6']['fixed_ver']           = '4.6.6';
fixes['4.6']['fixed_ver_display']   = '4.6.6 (changeset 4972c38)';
fixes['4.6']['affected_ver_regex']  = '^4\\.6\\.';
fixes['4.6']['affected_changesets'] = make_list("bd461fc", "c9c1bb6",
  "0fbf30a", "7e20b9b", "d1618f4", "9d534c1", "dbb3553", "e54a8c6",
  "8005ed3", "9a852e0", "d779cc1", "c93bcf9", "15adcf3", "d7b8190",
  "2b1457f", "a357880", "ee23fcc", "5651015", "225e9c7", "3c70619",
  "1222333", "75bdd69", "8994cf3", "642c603", "c25ea9a", "feba571",
  "0163087", "44c2666", "db743b0", "41a5cce", "4e1b9e9", "4d21549",
  "ff4800c", "2613a1b", "8335c8a", "ab20c5c", "9089da9", "8edfc82",
  "af5b61a", "ec05090", "75263f7", "f7e273a", "03c7d2c", "9ce1a71",
  "a735c7a", "44ad7f6", "91dc902", "a065841", "c6e9e60", "f94c11d",
  "45ddc4e", "1ca93b7", "8c0c36e", "6e43623", "47d3e73", "ea80245",
  "37bb22b", "9b0c2a2", "8d3fe28", "be63d66", "9454e30", "aad5a67",
  "d8b0ebf", "f0208a4", "42b2c82", "57318e1", "9f22d72", "e0353b4",
  "76f1549", "9bac910", "c7a43e3", "913d4f8", "c5881c5", "b0239cd",
  "78fd0c3", "9079e0d", "1658a87", "22b6dfa", "a8cd231", "629eddd",
  "64c03bb", "b4660b4", "1ac8162", "747df3c", "5ae011e", "f974d32",
  "3300ad3", "d708b69");

fixes['4.7']['fixed_ver']           = '4.7.5';
fixes['4.7']['fixed_ver_display']   = '4.7.5-pre (changeset c15b8dc)';
fixes['4.7']['affected_ver_regex']  = '^4\\.7\\.';
fixes['4.7']['affected_changesets'] = make_list("640691d", "69dcb65",
  "ade3bca", "c64e0c1", "e54670f", "7d56ef3", "aac4cbe", "68420b4",
  "e09548d", "be261bd", "327a783", "9f08fce", "4a38ec2", "65c9e06",
  "84d47ac", "b7dae55", "b2b7fe1", "c947e1e", "b1ae126", "72450c8",
  "e9220b4", "f961688", "91f7e46", "f291c01", "3cf4e29", "8860219",
  "62a2624", "c3f8df3", "3877c02", "f0ed5f9", "160b53c", "e131309",
  "9ede1ac", "d0cfbe8", "d596e6a", "f50ea84", "de3bdaa", "766990b",
  "4ac0229", "bafd63f", "d5bb425", "003ec3e", "fd884d6", "50c68df",
  "1bdcc9f", "2914ef5", "62b9706", "624abdc", "d7b73ed", "112c49c",
  "a5b0fa4", "e19d0af", "e19517a", "9b76908", "46025e3", "0e6c6fc",
  "40c4410", "f3b76b6", "4c937e2", "2307798", "7089465", "375896d",
  "99474d1", "f407332", "1c58d74", "d02140f", "fae9dd5", "caae052",
  "c90b5c1", "5b1c9fe", "2e6775e", "f2d19fb", "0baeec6", "664433a",
  "b3dfadc", "8f14027", "1967ced", "c3ddeca", "b9c150e", "5a99156",
  "4f34d9f", "4133de7", "b3981ea", "184f259", "67966a9", "af3f585");

fixes['4.8']['fixed_ver']           = '4.8.4';
fixes['4.8']['fixed_ver_display']   = '4.8.4-pre (changeset 141be84)';
fixes['4.8']['affected_ver_regex']  = '^4\\.8\\.';
fixes['4.8']['affected_changesets'] = make_list("bb49733", "48faa50",
  "5938aa1", "d11783c", "8e1e3c7", "99ed786", "76bdfe8", "fee4689",
  "c0bfde6", "64c1742", "8615385", "e09a5c2", "ff570a3", "e6bcb41",
  "29e7171", "c3d195c", "2cd189e", "afdad6a", "532ccf4", "da49e51",
  "ca9583d", "479b879", "2eefd92", "60c50f2", "1838e21", "5732a8e",
  "987b08d", "eadcd83", "ef2464c", "17bfbc8", "499391b", "87cb0e2", "393de92");

fixes['4.9']['fixed_ver']           = '4.9.2';
fixes['4.9']['fixed_ver_display']   = '4.9.2-pre (changeset e9bff96)';
fixes['4.9']['affected_ver_regex']  = '^4\\.9\\.';
fixes['4.9']['affected_changesets'] = make_list("8f42f0a", "aafb8ac",
  "88fbabc", "3b10e12", "7d5f8b3", "59999ae", "79d5197", "68c76d7",
  "bda3283", "a24b755", "13a30ba", "0177bf5", "2fdee60", "186c3c6",
  "e57d4d0", "1dcfd39", "f11cf29", "bd53bc8", "7648049", "602633e",
  "6fef46d", "30b9929", "447dce8", "29df8a5", "6403b50", "628b6af",
  "237a58b", "f0f7ce5", "d6e9725", "9aaa208", "40f9ae9", "ade9554",
  "a0ed034", "4d01dbc", "22379b6", "6e13ad7", "0d32237", "4ba59bd",
  "2997c5e", "751c879", "a2567d6", "9f79e8d", "fba48ef", "3790833",
  "50450c1", "2ec7ccb", "dc7d465", "1e09746", "87ea781", "96990e2",
  "2213ffe", "c3774d1", "f559d50", "f877aab", "0c3d524", "4d190d7",
  "a4a4abf", "432f715", "389df4f", "d6fe186", "6a39a56", "d9ade82",
  "c09e166", "df6db6c", "986fcb8", "da8c866", "47a7e3b", "57205c4",
  "09d7c30", "8edff60", "fe1147d", "78c61ba", "c9afe26", "4bd6306",
  "a20f838", "984bb18", "1b0029c", "32e364c", "d3db9e3", "c553285",
  "6260c47", "d1cca07", "0a0dcdc", "fb51cab", "61c13ed", "52ad651");

fixes['4.10']['fixed_ver']           = '4.10.1';
fixes['4.10']['fixed_ver_display']   = '4.10.1-pre (changeset 16edf98)';
fixes['4.10']['affected_ver_regex']  = '^4\\.10\\.';
fixes['4.10']['affected_changesets'] = make_list("e2ceb2e", "1b1c059",
  "5e91fc4", "3921128", "cd2e143", "3181472", "5644514", "db12743",
  "bc0e599", "fc81946", "ce7d7c0", "a695f8d", "92efbe8", "8baba87",
  "79891ef", "641c11e", "05eba93", "a69cfdf", "0f4be6e", "0a7e6b5",
  "65ee6e0", "129880d", "c513244", "0e12c2c", "6aaf353", "32babfc",
  "47bbcb2", "8743fc2", "1830b20", "ab95cb0", "d02ef3d", "e32f814",
  "c534ab4", "be3138b", "79012ea", "bbd093c", "a69a8b5", "f167ebf",
  "c4c0187", "19ad8a7", "3caf32c", "df7be94", "f379b70", "728fadb",
  "9281129", "cae6e15", "d1f4283", "0f7a4fa", "b829d42", "7cccd6f",
  "234f481", "57dc197", "7209b8b", "910dd00", "50d24b9", "c89c622",
  "3b8d88d", "cdb1fb4", "a401864", "a87ec48", "9dc5eda", "135b67e",
  "682a9d8", "19dcd8e", "e5364c3", "e2dc7b5", "c8f4f45", "4150501",
  "ab7be6c", "f3fb667");

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
  "Installed version", display_version,
  "Fixed version", fix,
  "Path", path
);

order  = make_list("Path", "Installed version", "Fixed version");
report = report_items_str(report_items:items, ordered_fields:order) + '\n';

security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);

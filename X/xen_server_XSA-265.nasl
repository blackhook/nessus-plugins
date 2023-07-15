#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111380);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2018-12893");
  script_bugtraq_id(104572);
  script_xref(name:"IAVB", value:"2018-B-0094-S");

  script_name(english:"Xen Project x86 Debug Exception Handling Local DoS (XSA-265)");
  script_summary(english:"Checks 'xl info' output for the Xen hypervisor version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor
installed on the remote host is affected by a local denial of service
vulnerability.

Note that Nessus has checked the changeset versions based on the
xen.git change log. Nessus did not check guest hardware configurations
or if patches were applied manually to the source code before a
recompile and reinstall.");
  script_set_attribute(attribute:"see_also", value:"http://xenbits.xen.org/xsa/advisory-265.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/gitweb/?p=xen.git;a=summary");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12893");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
fixes['4.6']['fixed_ver_display']   = '4.6.6 (changeset a544804)';
fixes['4.6']['affected_ver_regex']  = '^4\\.6\\.';
fixes['4.6']['affected_changesets'] = make_list("2642b56", "03938ba",
  "542f711", "90dc163", "61a9fc5", "a671bd6", "365ecff", "237236a",
  "aa5a889", "3e3c11b", "8a2e1db", "cb0230a", "4336ffa", "3df7d47",
  "5ccba18", "991dd4c", "331a1af", "035c96f", "bfe8f3e", "4f0509d",
  "2f99d68", "0d3904f", "342a02f", "2d8e87e", "ac659af", "c1be09e",
  "e7b723b", "cd5232a", "f9f9634", "6981351", "12b9fca", "916ef0d",
  "055abe4", "c4333f5", "3d6970d", "a0db1f2", "6a74f4e", "5278a9a",
  "c53663a", "c5339c5", "3b96676", "2f3cde3", "acd8661", "5ddc3f8",
  "927aca7", "b4b553d", "b766574", "10898d7", "0b38930", "33f70b8",
  "cf03d32", "525c381", "4c1e2d3", "021009e", "4972c38", "bd461fc",
  "c9c1bb6", "0fbf30a", "7e20b9b", "d1618f4", "9d534c1", "dbb3553",
  "e54a8c6", "8005ed3", "9a852e0", "d779cc1", "c93bcf9", "15adcf3",
  "d7b8190", "2b1457f", "a357880", "ee23fcc", "5651015", "225e9c7",
  "3c70619", "1222333", "75bdd69", "8994cf3", "642c603", "c25ea9a",
  "feba571", "0163087", "44c2666", "db743b0", "41a5cce", "4e1b9e9",
  "4d21549", "ff4800c", "2613a1b", "8335c8a", "ab20c5c", "9089da9",
  "8edfc82", "af5b61a", "ec05090", "75263f7", "f7e273a", "03c7d2c",
  "9ce1a71", "a735c7a", "44ad7f6", "91dc902", "a065841", "c6e9e60",
  "f94c11d", "45ddc4e", "1ca93b7", "8c0c36e", "6e43623", "47d3e73",
  "ea80245", "37bb22b", "9b0c2a2", "8d3fe28", "be63d66", "9454e30",
  "aad5a67", "d8b0ebf", "f0208a4", "42b2c82", "57318e1", "9f22d72",
  "e0353b4", "76f1549", "9bac910", "c7a43e3", "913d4f8", "c5881c5",
  "b0239cd", "78fd0c3", "9079e0d", "1658a87", "22b6dfa", "a8cd231",
  "629eddd", "64c03bb", "b4660b4", "1ac8162", "747df3c", "5ae011e",
  "f974d32", "3300ad3", "d708b69");

fixes['4.7']['fixed_ver']           = '4.7.5';
fixes['4.7']['fixed_ver_display']   = '4.7.5 (changeset f9898e7)';
fixes['4.7']['affected_ver_regex']  = '^4\\.7\\.';
fixes['4.7']['affected_changesets'] = make_list("253c3ec", "839826b",
  "55674ed", "0feed48", "a8d37ee", "117ef5e", "536d16c", "196932a",
  "0d44ee0", "f9b8c11", "ed4f56d", "3f5bd56", "03bf349", "375c01e",
  "acdf07d", "53c6a02", "466ab42", "870d737", "fb665b3", "6678f08",
  "bd63f04", "340c686", "55c1e84", "88f810a", "ea94f1e", "9299683",
  "8c699a0", "0b5b62a", "ff11aaf", "f666dab", "366e041", "5d271d5",
  "5d8c6fd", "226c231", "6de86cf", "ce22cc3", "4f713cf", "0b6c7b4",
  "2bc2e1f", "11fd624", "3478fb7", "0bc0693", "be0d7af", "d355f02",
  "236b8be", "e9281ad", "fb70754", "a6a2b5a", "54ff338", "1bd5a36",
  "5fc0102", "a8ef075", "e613050", "2fbc006", "1619cff", "5c81317",
  "912aa9b", "63b140f", "62b1879", "9680710", "dca80ab");

fixes['4.8']['fixed_ver']           = '4.8.4';
fixes['4.8']['fixed_ver_display']   = '4.8.4-pre (changeset 5fd28d2)';
fixes['4.8']['affected_ver_regex']  = '^4\\.8\\.';
fixes['4.8']['affected_changesets'] = make_list("d615412", "9a7fa68",
  "b736afd", "b9b9d9e", "028656f", "c1aaad5", "c5a5692", "1522a81",
  "37b3dfd", "f8a489f", "0954b11", "266d511", "2d97baa", "61fc6a4",
  "73b68d2", "811c168", "eef72b8", "ae0a87e", "b494c13", "c36aaca",
  "1afb894", "845d2b6", "9d73586", "7f4ae16", "05b41f2", "618a96e",
  "455a429", "1fd1973", "ef14d39", "c696ef0", "68d02a7", "b0ea18e",
  "e60a287", "9419337", "cc0bb3b", "197e605", "eaa9d0a", "d66898a",
  "f2837b5", "0f475fe", "210bd51", "b4ad8a6", "4cdd4cc", "193130f",
  "7f2959f", "9cba9ae", "f99bc15", "44c709e", "c10ddc1", "2bef7bf",
  "326d25f", "3f59d0b", "a89390b", "40c4ab8", "90676b7", "1052a21",
  "a2f02df", "501718a", "957ff30", "1e9ac23", "95befc6", "372583c",
  "202aaf8", "e4e9632", "a753be1", "8f9846f", "0864795", "866deda",
  "c67e19f", "bc6414f", "883c8db", "7db1c43", "813fe21", "3cadc8b",
  "f7bf4d2", "14217cb", "ce185fb", "a2700ca", "b19b206", "a442d40",
  "1901f62", "1581910", "15f57b8", "7ef31c0", "bc8aa42", "30a153d",
  "da92664", "6b08396", "f6ae9c0", "ad9ddc3", "22d2146", "f9adc12",
  "e27fd5c", "03f9474", "c31070f", "1093876", "141be84", "bb49733",
  "48faa50", "5938aa1", "d11783c", "8e1e3c7", "99ed786", "76bdfe8",
  "fee4689", "c0bfde6", "64c1742", "8615385", "e09a5c2", "ff570a3",
  "e6bcb41", "29e7171", "c3d195c", "2cd189e", "afdad6a", "532ccf4",
  "da49e51", "ca9583d", "479b879", "2eefd92", "60c50f2", "1838e21",
  "5732a8e", "987b08d", "eadcd83", "ef2464c", "17bfbc8", "499391b",
  "87cb0e2", "393de92");

fixes['4.9']['fixed_ver']           = '4.9.3';
fixes['4.9']['fixed_ver_display']   = '4.9.3-pre (changeset ad08a1b)';
fixes['4.9']['affected_ver_regex']  = '^4\\.9\\.';
fixes['4.9']['affected_changesets'] = make_list("c50b1f6", "238007d",
  "0b1904c", "859fc55", "1c6b8f2", "f51d368", "8689cd1", "fc72347",
  "27b0dcd", "8d874a8", "1284b90", "12259ff", "516ac8a", "ed217c9",
  "11eb72e", "3f85ebb", "1ed3466", "37c3cb4", "2aca1d7", "22a6433",
  "8a29d83", "14a2ad6", "c6d09b2", "e5de993", "c2029b4", "5633efa",
  "13cb0c2", "da140c6", "39ab89d", "a29695c", "74fa955", "b3277ca",
  "cf264eb", "809d543", "002ea4d", "1f183b5", "150cdd9", "f7889b3",
  "903f2f6", "4bbed1c", "2303a9d", "d674b6e", "52fa2f7", "62bd851",
  "c06ec81", "dbb06d3", "24fa3fa", "b9b5a03", "35a71c6", "b844573",
  "48dd543", "7866e11", "db7accf", "921bff4", "c147505", "dc527ff",
  "781e23a", "72ca580", "47d41f6", "7a59015", "259bee9", "6d4c4f0", "3e010f5");

fixes['4.10']['fixed_ver']           = '4.10.2';
fixes['4.10']['fixed_ver_display']   = '4.10.2-pre (changeset 42219af)';
fixes['4.10']['affected_ver_regex']  = '^4\\.10\\.';
fixes['4.10']['affected_changesets'] = make_list("1d5a9ec", "eeb1576",
  "4b9dc6d", "52447b3", "7b35e78", "8d48204", "b3a7f2f", "fb78102",
  "245eaee", "18833a8", "72e5b16", "27a4161", "23114db", "6300cdd",
  "2a0913e", "daaf3dd", "c2b84e7", "908ddbb", "c75bbf1", "e9dc0a6",
  "470daef", "c9fdfbb", "49aebf4", "48ad1ab", "98a285c", "cb2a83f",
  "51b7b5d", "840d683", "ec50d21", "a035518", "8342e3f", "aaf66de",
  "7e21b75", "f155f55", "3a903b3", "2e2f337", "850e5ad", "13fa2a4",
  "ade8f98", "a7f8880", "3bb756b", "1aa6305", "d93ae63", "6b8d820", "f253feb");

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

security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);

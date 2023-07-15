#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112157);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2018-15468");
  script_xref(name:"IAVB", value:"2018-B-0111-S");

  script_name(english:"Xen Project MSR_DEBUGCTL 'Branch Trace Store' DoS (XSA-269)");
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
  script_set_attribute(attribute:"see_also", value:"http://xenbits.xen.org/xsa/advisory-269.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/gitweb/?p=xen.git;a=summary");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15468");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/28");

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
fixes['4.6']['fixed_ver_display']   = '4.6.6 (changeset 14402dc)';
fixes['4.6']['affected_ver_regex']  = '^4\\.6\\.';
fixes['4.6']['affected_changesets'] = make_list("45f6a27", "4c8d9f8",
  "1840f82", "a80ce17", "7d98594", "f30c9b6", "a1b8d86", "ff1d0b6",
  "3bd7cf6", "55c7bd6", "98d7948", "e0981f6", "91cf29f", "a0c3f80",
  "cf7d9d1", "170c48b", "c39cd00", "2d69b6d", "03ba272", "1fa0ecb",
  "598a375", "b7b7c4d", "ba7d011", "a544804", "2642b56", "03938ba",
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

fixes['4.7']['fixed_ver']           = '4.7.6';
fixes['4.7']['fixed_ver_display']   = '4.7.6 (changeset 59732fd)';
fixes['4.7']['affected_ver_regex']  = '^4\\.7\\.';
fixes['4.7']['affected_changesets'] = make_list("3f7fd2b", "bcbd8b9",
  "dfee811", "95ff4e1", "ded2a37", "87dba80", "fe028e6", "a51e6a3",
  "0e66281", "51d9780", "91ca84c", "bce2dd6", "fa807e2", "97aff08",
  "e90e243", "c0e854b", "9858a1f", "a404136", "dc111e9", "0873699", "280a556");

fixes['4.8']['fixed_ver']           = '4.8.5';
fixes['4.8']['fixed_ver_display']   = '4.8.5-pre (changeset ed6fcdb)';
fixes['4.8']['affected_ver_regex']  = '^4\\.8\\.';
fixes['4.8']['affected_changesets'] = make_list("0406164", "e3d0ce3",
  "c00fabc", "3478439", "b81b74a", "b289403", "47fbc6e", "ee7bcea",
  "df5bbf7", "d96893f", "15508b3", "790ed15", "d838957", "aa45015",
  "b149b06", "c117d09", "e343ee8", "5566272", "f049cd6", "6dc0bc5",
  "37a1b4a", "f6a31ed", "08eda97", "96bf2db", "23975f5", "f3b0cdb",
  "f5ef10d", "de172b0", "3686d09", "4aec0c7");

fixes['4.9']['fixed_ver']           = '4.9.3';
fixes['4.9']['fixed_ver_display']   = '4.9.3-pre (changeset 8231311)';
fixes['4.9']['affected_ver_regex']  = '^4\\.9\\.';
fixes['4.9']['affected_changesets'] = make_list("ab34a43", "023da62",
  "01b624b", "c4fda1d", "946badc", "db356a4", "0c9baf6", "c847824",
  "66a3e68", "ec32158", "6522c1c", "284c601", "3d2dc31", "a1b223b",
  "a894c9d", "d866881", "819e114", "c6055c5", "cc15a7b", "15124d9",
  "7f4a82d", "e40bfc1", "53b22ad", "ec3030f", "84dd174", "c4d86c6",
  "a6ac51a", "514785c", "f904bdd", "036006f", "f5c692a", "612ff3c",
  "555ef37", "e76d0f7", "19f4f87", "c4cb7d3", "8cdaac2", "7fbbedd",
  "46863c6", "041844b", "0a9c2bd", "5d92007", "c257e35", "ad08a1b",
  "c50b1f6", "238007d", "0b1904c", "859fc55", "1c6b8f2", "f51d368",
  "8689cd1", "fc72347", "27b0dcd", "8d874a8", "1284b90", "12259ff",
  "516ac8a", "ed217c9", "11eb72e", "3f85ebb", "1ed3466", "37c3cb4",
  "2aca1d7", "22a6433", "8a29d83", "14a2ad6", "c6d09b2", "e5de993",
  "c2029b4", "5633efa", "13cb0c2", "da140c6", "39ab89d", "a29695c",
  "74fa955", "b3277ca", "cf264eb", "809d543", "002ea4d", "1f183b5",
  "150cdd9", "f7889b3", "903f2f6", "4bbed1c", "2303a9d", "d674b6e",
  "52fa2f7", "62bd851", "c06ec81", "dbb06d3", "24fa3fa", "b9b5a03",
  "35a71c6", "b844573", "48dd543", "7866e11", "db7accf", "921bff4",
  "c147505", "dc527ff", "781e23a", "72ca580", "47d41f6", "7a59015",
  "259bee9", "6d4c4f0", "3e010f5");

fixes['4.10']['fixed_ver']           = '4.10.2';
fixes['4.10']['fixed_ver_display']   = '4.10.2-pre (changeset 924a5ee)';
fixes['4.10']['affected_ver_regex']  = '^4\\.10\\.';
fixes['4.10']['affected_changesets'] = make_list("5fd0bb3", "9e7ee94",
  "0de39f3", "6504045", "b4d6690", "09b6924", "2450f34", "227da39",
  "07a9be7", "dcca8f0", "8af1a79", "93017a6", "6e57d28", "87c83af",
  "b07c76f", "541a105", "6f6207f", "6feafd8", "01eb262", "512d3e7",
  "74f437f", "371149b", "3607213", "7145525", "498716e", "fab92fc",
  "bc1289f", "4ccf397", "381fdae", "d976fe5", "a645331", "c220240",
  "78a86a7", "6e0e45a", "b81a8bf", "de578bc", "3bd7966", "dd07d3e",
  "b5e9f1e", "e0da0d9", "2308158", "b2444d2", "42219af", "1d5a9ec",
  "eeb1576", "4b9dc6d", "52447b3", "7b35e78", "8d48204", "b3a7f2f",
  "fb78102", "245eaee", "18833a8", "72e5b16", "27a4161", "23114db",
  "6300cdd", "2a0913e", "daaf3dd", "c2b84e7", "908ddbb", "c75bbf1",
  "e9dc0a6", "470daef", "c9fdfbb", "49aebf4", "48ad1ab", "98a285c",
  "cb2a83f", "51b7b5d", "840d683", "ec50d21", "a035518", "8342e3f",
  "aaf66de", "7e21b75", "f155f55", "3a903b3", "2e2f337", "850e5ad",
  "13fa2a4", "ade8f98", "a7f8880", "3bb756b", "1aa6305", "d93ae63",
  "6b8d820", "f253feb");

fixes['4.11']['fixed_ver']           = '4.11.1';
fixes['4.11']['fixed_ver_display']   = '4.11.1-pre (changeset 48fb482)';
fixes['4.11']['affected_ver_regex']  = '^4\\.11\\.';
fixes['4.11']['affected_changesets'] = make_list("fa79f9e", "1d32c21",
  "7b420e8", "8b35b97", "cfdd4e8", "218d403", "b52017c", "52b8f9a",
  "935e9c4", "61cc876", "4254e98", "6fe9726", "33ced72", "7de2155",
  "06d2a76", "543027c", "037fe82", "353edf1", "75313e4", "5908b48",
  "bd51a64", "0a2016c", "b53e0de", "a44cf0c", "ac35e05", "10c5482",
  "4bdeedb", "da33530", "e932371", "1fd87ba");

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

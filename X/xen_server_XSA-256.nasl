#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107099);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2018-7542");
  script_bugtraq_id(103175);

  script_name(english:"Xen arch_domain_create() Function Local APIC Assumption NULL Pointer Dereference Guest-to-host DoS (XSA-256)");
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
  script_set_attribute(attribute:"see_also", value:"http://xenbits.xen.org/xsa/advisory-256.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/gitweb/?p=xen.git;a=summary");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7542");

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

fixes['4.8']['fixed_ver']           = '4.8.4';
fixes['4.8']['fixed_ver_display']   = '4.8.4-pre (changeset 1093876)';
fixes['4.8']['affected_ver_regex']  = '^4\\.8\\.';
fixes['4.8']['affected_changesets'] = make_list("141be84", "bb49733",
  "48faa50", "5938aa1", "d11783c", "8e1e3c7", "99ed786", "76bdfe8",
  "fee4689", "c0bfde6", "64c1742", "8615385", "e09a5c2", "ff570a3",
  "e6bcb41", "29e7171", "c3d195c", "2cd189e", "afdad6a", "532ccf4",
  "da49e51", "ca9583d", "479b879", "2eefd92", "60c50f2", "1838e21",
  "5732a8e", "987b08d", "eadcd83", "ef2464c", "17bfbc8", "499391b",
  "87cb0e2", "393de92");

fixes['4.9']['fixed_ver']           = '4.9.2';
fixes['4.9']['fixed_ver_display']   = '4.9.2-pre (changeset 395cb3f)';
fixes['4.9']['affected_ver_regex']  = '^4\\.9\\.';
fixes['4.9']['affected_changesets'] = make_list("e9bff96", "8f42f0a",
  "aafb8ac", "88fbabc", "3b10e12", "7d5f8b3", "59999ae", "79d5197",
  "68c76d7", "bda3283", "a24b755", "13a30ba", "0177bf5", "2fdee60",
  "186c3c6", "e57d4d0", "1dcfd39", "f11cf29", "bd53bc8", "7648049",
  "602633e", "6fef46d", "30b9929", "447dce8", "29df8a5", "6403b50",
  "628b6af", "237a58b", "f0f7ce5", "d6e9725", "9aaa208", "40f9ae9",
  "ade9554", "a0ed034", "4d01dbc", "22379b6", "6e13ad7", "0d32237",
  "4ba59bd", "2997c5e", "751c879", "a2567d6", "9f79e8d", "fba48ef",
  "3790833", "50450c1", "2ec7ccb", "dc7d465", "1e09746", "87ea781",
  "96990e2", "2213ffe", "c3774d1", "f559d50", "f877aab", "0c3d524",
  "4d190d7", "a4a4abf", "432f715", "389df4f", "d6fe186", "6a39a56",
  "d9ade82", "c09e166", "df6db6c", "986fcb8", "da8c866", "47a7e3b",
  "57205c4", "09d7c30", "8edff60", "fe1147d", "78c61ba", "c9afe26",
  "4bd6306", "a20f838", "984bb18", "1b0029c", "32e364c", "d3db9e3",
  "c553285", "6260c47", "d1cca07", "0a0dcdc", "fb51cab", "61c13ed", "52ad651");

fixes['4.10']['fixed_ver']           = '4.10.1';
fixes['4.10']['fixed_ver_display']   = '4.10.1-pre (changeset a6780c1)';
fixes['4.10']['affected_ver_regex']  = '^4\\.10\\.';
fixes['4.10']['affected_changesets'] = make_list("16edf98", "e2ceb2e",
  "1b1c059", "5e91fc4", "3921128", "cd2e143", "3181472", "5644514",
  "db12743", "bc0e599", "fc81946", "ce7d7c0", "a695f8d", "92efbe8",
  "8baba87", "79891ef", "641c11e", "05eba93", "a69cfdf", "0f4be6e",
  "0a7e6b5", "65ee6e0", "129880d", "c513244", "0e12c2c", "6aaf353",
  "32babfc", "47bbcb2", "8743fc2", "1830b20", "ab95cb0", "d02ef3d",
  "e32f814", "c534ab4", "be3138b", "79012ea", "bbd093c", "a69a8b5",
  "f167ebf", "c4c0187", "19ad8a7", "3caf32c", "df7be94", "f379b70",
  "728fadb", "9281129", "cae6e15", "d1f4283", "0f7a4fa", "b829d42",
  "7cccd6f", "234f481", "57dc197", "7209b8b", "910dd00", "50d24b9",
  "c89c622", "3b8d88d", "cdb1fb4", "a401864", "a87ec48", "9dc5eda",
  "135b67e", "682a9d8", "19dcd8e", "e5364c3", "e2dc7b5", "c8f4f45",
  "4150501", "ab7be6c", "f3fb667");

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

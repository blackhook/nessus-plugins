#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102842);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_bugtraq_id(100496);
  script_xref(name:"IAVB", value:"2017-B-0115-S");

  script_name(english:"Xen Hypervisor Function Error Condition Handling Lock Release Failure Guest-to-Host DoS (XSA-235)");
  script_summary(english:"Checks 'xl info' output for the Xen hypervisor version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor
installed on the remote host is affected by flaw in the
xenmem_add_to_physmap_one() function in arch/arm/mm.c that is
triggered as the application fails to release a lock when handling
certain error conditions. This may allow a privileged attacker within
a guest to block a physical CPU, resulting in a denial of service.

This issue only affects ARM systems. x86 systems are not affected.

Note that Nessus has checked the changeset versions based on the
xen.git change log. Nessus did not check guest hardware configurations
or if patches were applied manually to the source code before a
recompile and reinstall.");
  script_set_attribute(attribute:"see_also", value:"http://xenbits.xen.org/xsa/advisory-235.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/gitweb/?p=xen.git;a=summary");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");

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

# XSA-235
fixes['4.5']['fixed_ver']           = '4.5.5';
fixes['4.5']['fixed_ver_display']   = '4.5.5 (changeset d5a5231)';
fixes['4.5']['affected_ver_regex']  = '^4\\.5\\.';
fixes['4.5']['affected_changesets'] = make_list("c5b0fe5", "136ff4e",
  "42c8ba5", "d38489d", "df59014", "3217129", "4964e86", "c079597",
  "6ec173b", "a373456", "0780e81", "e5ef76d", "25eaa86", "ae02360",
  "5597df9", "c5de05e", "773094e", "e39a248", "7b3712a", "be35327",
  "8825df1", "d7e3725", "6eb61e4", "b1fcfed", "5779d6a", "afdd77e",
  "c18367a", "7b7fd80", "b30e165", "62ef9b2", "8071724", "235b5d5",
  "a28b99d", "ff294fc", "bc01e2d", "da50922", "386cc94", "139960f",
  "ec3ddd6", "988929a", "1c48dff", "20d4248", "9610422", "cd76cd3",
  "455fd66", "b820c31", "ac3d8bc", "cde86fc", "1678521", "83cb2db",
  "43d06ef", "2b17bf4", "1a2bda5", "0bd7faf", "e3426e2", "37281bc",
  "27be856", "bdf3ef1", "cc325c0", "8e7b84d", "387b8ae", "34fbae7",
  "1530da2", "274a1f6", "b679cfa", "877b760", "cfe165d", "84e4e56",
  "e4ae4b0");

fixes['4.6']['fixed_ver']           = '4.6.6';
fixes['4.6']['fixed_ver_display']   = '4.6.6 (changeset 64c03bb)';
fixes['4.6']['affected_ver_regex']  = '^4\\.6\\.';
fixes['4.6']['affected_changesets'] = make_list("b4660b4", "1ac8162",
  "747df3c", "5ae011e", "f974d32", "3300ad3", "d708b69");

fixes['4.7']['fixed_ver']           = '4.7.4';
fixes['4.7']['fixed_ver_display']   = '4.7.4-pre (changeset 30d50f8)';
fixes['4.7']['affected_ver_regex']  = '^4\\.7\\.';
fixes['4.7']['affected_changesets'] = make_list("2dc3cdb", "5151257",
  "c9f3ca0", "e873251", "8aebf85", "c362cde", "fece08a");

fixes['4.8']['fixed_ver']           = '4.8.2';
fixes['4.8']['fixed_ver_display']   = '4.8.2-pre (changeset df8c4fa)';
fixes['4.8']['affected_ver_regex']  = '^4\\.8\\.';
fixes['4.8']['affected_changesets'] = make_list("c3c2df8", "236263f",
  "5c10e0e", "5afb94c", "f5211ce", "877591c", "460cd3b", "1e6c88f",
  "55cf609", "079550e", "f6f543f", "a332ac1", "1a147b5", "8652908",
  "1e40f87", "7dd85eb", "24809e0", "8d3dafb", "aedaa82", "a75d7ad",
  "125a3a9", "b859653", "429ad0d", "1959b49", "670bb9d", "270b9f8",
  "50ee10e", "e5da3cc", "982d477", "ca71eb3", "c7dab25", "ca97409",
  "a4bca7c", "fe5bbfd", "cb99078", "e1bcfb1", "2d37e90", "c427a81",
  "125e4d4", "9e6b2dd", "52d8380", "5026eb5", "e5ec23e", "79d2d5c",
  "b7d2c0f", "d584144", "d721af1", "72808a8", "173eb93", "d29cb49",
  "98cefcc", "e91a24c", "de1318b", "4057c6e", "834ea87", "efd2ff9",
  "19ad7c0", "1780c26", "8f6d1f9", "957dc0e", "12b1425", "a782d9d");

fixes['4.9']['fixed_ver']           = '4.9.1';
fixes['4.9']['fixed_ver_display']   = '4.9.1-pre (changeset 5ff1de3)';
fixes['4.9']['affected_ver_regex']  = '^4\\.9\\.';
fixes['4.9']['affected_changesets'] = make_list("692ed82", "9bf14bb",
  "c57b1f9", "6b147fd", "0e186e3", "afc5ebf", "266fc0e", "4698106",
  "f4f02f1", "0fada05", "ab4eb6c", "b29ecc7", "a11d14b", "107401e",
  "1b7834a");

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

items  = make_array("Installed version", display_version,
                    "Fixed version", fix,
                    "Path", path);
order  = make_list("Path", "Installed version", "Fixed version");
report = report_items_str(report_items:items, ordered_fields:order) + '\n';

security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);

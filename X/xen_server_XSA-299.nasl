#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(131133);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/10");

  script_cve_id("CVE-2019-18421");
  script_xref(name:"IAVB", value:"2019-B-0084-S");

  script_name(english:"Xen Restartable PV Type Change Operations Elevation of Privilege Vulnerability (XSA-299)");
  script_summary(english:"Checks the 'xl info' output for the Xen hypervisor version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor installed on the remote host is affected by an
elevation of privilege vulnerability due to race conditions in the pagetable promotion and demotion operations. An
authenticated, remote attacker can exploit this issue, by triggering race conditions and cause Xen to drop or retain
extra type counts, to get write access to in-use pagetables and potentially gain elevated privileges.

Note that Nessus has checked the changeset versions based on the xen.git change log. Nessus did not check guest hardware
configurations or if patches were applied manually to the source code before a recompile and reinstall.");
  # https://xenbits.xen.org/xsa/advisory-299.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ff583c8");
  # https://xenbits.xen.org/gitweb/?p=xen.git;a=summary
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e75f4bb");
  script_set_attribute(attribute:"solution", value:
"Apply the appropiate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18421");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/20");

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
fixes['4.8']['fixed_ver_display']   = '4.8.5';
fixes['4.8']['affected_ver_regex']  = '^4\\.8\\.';

fixes['4.9']['fixed_ver']           = '4.9.4';
fixes['4.9']['fixed_ver_display']   = '4.9.4';
fixes['4.9']['affected_ver_regex']  = '^4\\.9\\.';

fixes['4.10']['fixed_ver']           = '4.10.4';
fixes['4.10']['fixed_ver_display']   = '4.10.4';
fixes['4.10']['affected_ver_regex']  = '^4\\.10\\.';

fixes['4.11']['fixed_ver']           = '4.11.3';
fixes['4.11']['fixed_ver_display']   = '4.11.3-pre (changeset ee78046)';
fixes['4.11']['affected_ver_regex']  = '^4\\.11\\.';
fixes['4.11']['affected_changesets'] = make_list(
'05c14f6', '6fed54c', '766edd7', '657dc2d', 'be89e98', '273cf03', 'd78a967', 'c20ab0c', '5350514', '19bb4f5', 
'ca185ab', '0047407', 'aebe055', 'd6d52bc', '317de0a', '1b16093', 'ce7b549', '621b2d0', '8502a2c', '7f5f48d', 
'7824b9f', 'b52bcda', '27ff738', '6d36734', 'e2e653f', '9eac932', 'd4fe232', 'ba287c7', 'e33ce32', '28ed7a5', 
'527e324', '91836ce', '6eb3f76', 'cb86f3d', '8bfcd2e', 'fb1db30', 'b5433e7', 'b6ef69d', 'd27973c', 'ba6f5be', 
'4c6142e', '6e63afe', '5fcaaae', 'b0d4cec', 'c76e47d', 'a43eb8a', '3342ee9', 'b222046', '37ccdfd', '8bbb3e9', 
'ff5ddf0', '802f994', '10582ea', '4e95d85', 'da235ee', '32bdae2', 'b647da4', '1ec05c2', '9b91bec', 'dc3cd3d', 
'3311f10', '5fd47c5', '6af54f7', 'c250e2d', '08cb4b9', '8efcc0d', '1cf304f', 'c14026b', 'c719519', '93ad919', 
'fcc4f5d', '2f7f16c', 'fddda5d', 'd0dc725', '7ca58e5', 'be800a1');

fixes['4.12']['fixed_ver']           = '4.12.2';
fixes['4.12']['fixed_ver_display']   = '4.12.2-pre (changeset db91ac4)';
fixes['4.12']['affected_ver_regex']  = '^4\\.12\\.';
fixes['4.12']['affected_changesets'] = make_list(
'5698505', '28c209e', '1b1295e', '94ff3cf', '3918f99', '81a0e12', '113282b', '828e277', 'f5af2b9', '09513ab', 
'3dc7b91', '3d83e00', '26b8dd7', '5572ba9', 'bb4c1a8', '81feea0', '9f74689', '5f1c9e4', '4b5cc95', 'ab1e6a7', 
'801acf8', '97b4698', 'e28f7d6', '4fe70a1', 'c288534', '2a8209f', 'bc87a2d', '8fbf991', '8382d02', 'e142459', 
'0d210c0', '89de994', '9187046', '634a4d3', 'b6ee060', '61770e7', '599d6d2', '9d73672', 'e6ccef1', '2b84ade', 
'd2ca39f', '04a2fe9', '3c10d06', '4e145fd', '07ec556', '847fc70', '5ea346e', 'd42fb06', '32443f6', 'a5fc553', 
'b465705', 'd04466f', 'be2cd69', '50b9123', '8b129ba', 'b527557');

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

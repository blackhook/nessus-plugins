#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(132934);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/10");

  script_cve_id("CVE-2019-18423");
  script_xref(name:"IAVB", value:"2019-B-0084-S");

  script_name(english:"Xen Denial of Service Vulnerability (XSA-301)");
  script_summary(english:"Checks the 'xl info' output for the Xen hypervisor version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen Hypervisor installed on the remote host is affected by a denial
of service vulnerability due to improper validation of input data. An authenticated, remote attack can exploit this, via
a specially crafted hypercall followed by an access to an address that passes the sanity
check but causes a hypervisor crash . 

Note that Nessus has checked the changeset versions based on the xen.git change log. Nessus did not check guest hardware
configurations or if patches were applied manually to the source code before a recompile and reinstall.");
  # https://xenbits.xen.org/xsa/advisory-301.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7258df64");
  script_set_attribute(attribute:"solution", value:
"Apply the appropiate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18423");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
fixes['4.8']['fixed_ver_display']   = '4.8.5 (changeset 4ffb12e)';
fixes['4.8']['affected_ver_regex']  = '^4\\.8\\.';
fixes['4.8']['affected_changesets'] = make_list(
'929ec99', 'ae9ec06', '6c4efc1', '2867c7e', '611ca5b', '12ac129', 'f1bf612', '422d637', '6699295', '10105fa', 
'bf78103', '219b64d', 'f03e1b7', '048bbe8', '151406a', 'd02aeba', '960670a', '4ed28df', 'c67210f', 'd4d3ab3', 
'd87211e', 'a9acbcf', '514de95', '48ab64f', '181ed91', 'c3fdb25', '7feb3cc', '343c611', '257048f', '491e033',
'3683ec2', 'a172d06', '52092fc', 'e0d6cde', 'cc1c9e3', 'f6a4af3', 'ece24c0', '175a698', '48f5cf7', '9eb6247',
'31cbd18', 'fcf002d', 'ecbf88a', 'd929136', '8099c04', '752fb21', 'a95a103', '3dcb199', '55da36f', '160f050',
'194b7a2', 'a556287', '2032f86', 'e9d860f', 'a1f8fe0', '5bc841c', '4539dbc', 'dcd6efd', '88fb22b', '1c4ab1e',
'40ad83f', '51c3b69', '44aba8b', '067ec7d', 'f51d8e5', 'b9b0c46', '908e768');

fixes['4.9']['fixed_ver']           = '4.9.4';
fixes['4.9']['fixed_ver_display']   = '4.9.4 (changeset 632fb4e)';
fixes['4.9']['affected_ver_regex']  = '^4\\.9\\.';
fixes['4.9']['affected_changesets'] = make_list(
'4608c6d', '7daacca', '859e48e', '5be2dd0', 'b0147bd', 'cadd66a', 'd3c4b60', 'd59f5c4', '44303c6', '79538ba', 
'80c3157', '73f1a55', 'bc20fb1', '754a531', '7b032c2', 'ff4fdf0', '8d2a688', 'b9013d7', 'bc8e5ec', '34907f5',
'e70bf7e', 'fa0b891', '3a8177c', '04ec835', '8d63ec4', '1ff6b4d', 'f092d86', 'e4b534f', '87c49fe', '19becb8',
'43775c0', 'f6b0f33', 'a17e75c', '67530e7', 'f804549', '84f81a8', '56aa239', '105db42', 'd9da3ea', 'ac90240',
'3db28b0', '9b6f1c0', '0c4bbad', '917d8d3', '3384ea4', '352421f', '04e9dcb', '1612f15', 'f952b1d', '63d9330',
'f72414a', 'ac3a5f8', '1ae6b8e', '1dd3dcc', '7390fa1', '7e78dc4', '8fdfb1e', '55d36e2', '045f37c', 'dd7e637',
'7a40b5b', 'f5acf97');

fixes['4.10']['fixed_ver']           = '4.10.4';
fixes['4.10']['fixed_ver_display']   = '4.10.4 (changeset 13ad331)';
fixes['4.10']['affected_ver_regex']  = '^4\\.10\\.';
fixes['4.10']['affected_changesets'] = make_list(
'61b75d9', 'e70e7bf', 'e966e2e', 'dfa16a1', 'a71e199', 'c98be9e', 'a548e10', 'd3c0e84', '53b1572', '7203f9a',
'6d1659d', 'a782173', '24e90db', '0824bc6', 'e6f3135', '3131bf9');

fixes['4.11']['fixed_ver']           = '4.11.3';
fixes['4.11']['fixed_ver_display']   = '4.11.3-pre (changeset 56767b7)';
fixes['4.11']['affected_ver_regex']  = '^4\\.11\\.';
fixes['4.11']['affected_changesets'] = make_list(
'952f362', '7c3c7d8', 'ee78046', '05c14f6', '6fed54c', '766edd7', '657dc2d', 'be89e98', '273cf03', 'd78a967',
'c20ab0c', '5350514', '19bb4f5', 'ca185ab', '0047407', 'aebe055', 'd6d52bc', '317de0a', '1b16093', 'ce7b549',
'621b2d0', '8502a2c', '7f5f48d', '7824b9f', 'b52bcda', '27ff738', '6d36734', 'e2e653f', '9eac932', 'd4fe232',
'ba287c7', 'e33ce32', '28ed7a5', '527e324', '91836ce', '6eb3f76', 'cb86f3d', '8bfcd2e', 'fb1db30', 'b5433e7',
'b6ef69d', 'd27973c', 'ba6f5be', '4c6142e', '6e63afe', '5fcaaae', 'b0d4cec', 'c76e47d', 'a43eb8a', '3342ee9',
'b222046', '37ccdfd', '8bbb3e9', 'ff5ddf0', '802f994', '10582ea', '4e95d85', 'da235ee', '32bdae2', 'b647da4',
'1ec05c2', '9b91bec', 'dc3cd3d', '3311f10', '5fd47c5', '6af54f7', 'c250e2d', '08cb4b9', '8efcc0d', '1cf304f',
'c14026b', 'c719519', '93ad919', 'fcc4f5d', '2f7f16c', 'fddda5d', 'd0dc725', '7ca58e5', 'be800a1');

fixes['4.12']['fixed_ver']           = '4.12.2';
fixes['4.12']['fixed_ver_display']   = '4.12.2-pre (changeset df67757)';
fixes['4.12']['affected_ver_regex']  = '^4\\.12\\.';
fixes['4.12']['affected_changesets'] = make_list(
'bbcd6c5', '7575728', 'db91ac4', '5698505', '28c209e', '1b1295e', '94ff3cf', '3918f99', '81a0e12', '113282b', 
'828e277', 'f5af2b9', '09513ab', '3dc7b91', '3d83e00', '26b8dd7', '5572ba9', 'bb4c1a8', '81feea0', '9f74689',
'5f1c9e4', '4b5cc95', 'ab1e6a7', '801acf8', '97b4698', 'e28f7d6', '4fe70a1', 'c288534', '2a8209f', 'bc87a2d',
'8fbf991', '8382d02', 'e142459', '0d210c0', '89de994', '9187046', '634a4d3', 'b6ee060', '61770e7', '599d6d2',
'9d73672', 'e6ccef1', '2b84ade', 'd2ca39f', '04a2fe9', '3c10d06', '4e145fd', '07ec556', '847fc70', '5ea346e',
'd42fb06', '32443f6', 'a5fc553', 'b465705', 'd04466f', 'be2cd69', '50b9123', '8b129ba', 'b527557');


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

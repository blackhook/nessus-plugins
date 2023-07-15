#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134170);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/03");

  script_cve_id("CVE-2019-19578");

  script_name(english:"Xen Denial of Service Vulnerability (XSA-304)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor installed on the remote host is affected by a denial
of service vulnerability due to an incorrect fix for CVE-2017-15595 which incorrectly drops some linear_pt_entry counts. 
A local, attacker could exploit this issue, by making loops or other arbitrary chains of linear pagetables, as described
in XSA-240. A malicious or buggy PV guest may cause the hypervisor to crash, resulting in denial of service affecting
the entire host. Privilege escalation and information leaks cannot be excluded.");
  # https://xenbits.xen.org/xsa/advisory-309.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bda0f738");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch or workaround according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19578");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("xen_server_detect.nbin");
  script_require_keys("installed_sw/Xen Hypervisor", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('install_func.inc');
include('misc_func.inc');

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
fixes['4.8']['fixed_ver_display']   = '4.8.5 (changeset bafcd7f)';
fixes['4.8']['affected_ver_regex']  = '^4\\.8\\.';
fixes['4.8']['affected_changesets'] = make_list(
'76dad2e', '714a65a', 'd1d3431', 'a260e93', 'ec6c25e', '1486caf', '4c666a7', 'a70ba89', '6082eac', 'fb93a9b', '80e67e4',
'dc62982', 'aca2511', '17c3324', '4ffb12e', '929ec99', 'ae9ec06', '6c4efc1', '2867c7e', '611ca5b', '12ac129', 'f1bf612',
'422d637', '6699295', '10105fa', 'bf78103', '219b64d', 'f03e1b7', '048bbe8', '151406a', 'd02aeba', '960670a', '4ed28df',
'c67210f', 'd4d3ab3', 'd87211e', 'a9acbcf', '514de95', '48ab64f', '181ed91', 'c3fdb25', '7feb3cc', '343c611', '257048f',
'491e033', '3683ec2', 'a172d06', '52092fc', 'e0d6cde', 'cc1c9e3', 'f6a4af3', 'ece24c0', '175a698', '48f5cf7', '9eb6247',
'31cbd18', 'fcf002d', 'ecbf88a', 'd929136', '8099c04', '752fb21', 'a95a103', '3dcb199', '55da36f', '160f050', '194b7a2',
'a556287', '2032f86', 'e9d860f', 'a1f8fe0', '5bc841c', '4539dbc', 'dcd6efd', '88fb22b', '1c4ab1e', '40ad83f', '51c3b69',
'44aba8b', '067ec7d', 'f51d8e5', 'b9b0c46', '908e768');

fixes['4.9']['fixed_ver']           = '4.9.4';
fixes['4.9']['fixed_ver_display']   = '4.9.4 (changeset ec229c2)';
fixes['4.9']['affected_ver_regex']  = '^4\\.9\\.';
fixes['4.9']['affected_changesets'] = make_list(
'e879bfe', 'ce126c9', '4b69427', '8d1ee9f', 'e60b3a9', '25f5530', '49db55f', 'fa34ed5', '704f7ec', 'a930a74', '8c52ee2',
'2e15a19', '70639ac', 'c3b479d', 'e349eae', '632fb4e', '4608c6d', '7daacca', '859e48e', '5be2dd0', 'b0147bd', 'cadd66a',
'd3c4b60', 'd59f5c4', '44303c6', '79538ba', '80c3157', '73f1a55', 'bc20fb1', '754a531', '7b032c2', 'ff4fdf0', '8d2a688',
'b9013d7', 'bc8e5ec', '34907f5', 'e70bf7e', 'fa0b891', '3a8177c', '04ec835', '8d63ec4', '1ff6b4d', 'f092d86', 'e4b534f',
'87c49fe', '19becb8', '43775c0', 'f6b0f33', 'a17e75c', '67530e7', 'f804549', '84f81a8', '56aa239', '105db42', 'd9da3ea',
'ac90240', '3db28b0', '9b6f1c0', '0c4bbad', '917d8d3', '3384ea4', '352421f', '04e9dcb', '1612f15', 'f952b1d', '63d9330',
'f72414a', 'ac3a5f8', '1ae6b8e', '1dd3dcc', '7390fa1', '7e78dc4', '8fdfb1e', '55d36e2', '045f37c', 'dd7e637', '7a40b5b',
'f5acf97');

fixes['4.10']['fixed_ver']           = '4.10.4';
fixes['4.10']['fixed_ver_display']   = '4.10.4 (changeset 07e546e)';
fixes['4.10']['affected_ver_regex']  = '^4\\.10\\.';
fixes['4.10']['affected_changesets'] = make_list(
'fefa5f9', 'c9f9ff7', '406d40d', 'e489955', '37139f1', 'fde09cb', '804ba02', 'e8c3971', 'a8c4293', 'aa40452', '1da3dab',
'e5632c4', '902e72d', '6a14610', 'ea815b2', '13ad331', '61b75d9', 'e70e7bf', 'e966e2e', 'dfa16a1', 'a71e199', 'c98be9e',
'a548e10', 'd3c0e84', '53b1572', '7203f9a', '6d1659d', 'a782173', '24e90db', '0824bc6', 'e6f3135', '3131bf9');

fixes['4.11']['fixed_ver']           = '4.11.4';
fixes['4.11']['fixed_ver_display']   = '4.11.4-pre (changeset 3d2cc67)';
fixes['4.11']['affected_ver_regex']  = '^4\\.11\\.';
fixes['4.11']['affected_changesets'] = make_list('d4a67be', 'b8a8278', '06555fd');

fixes['4.12']['fixed_ver']           = '4.12.2';
fixes['4.12']['fixed_ver_display']   = '4.12.2-pre (changeset 5eaba24)';
fixes['4.12']['affected_ver_regex']  = '^4\\.12\\.';
fixes['4.12']['affected_changesets'] = make_list(
'268e5f6', '0e3fd5d', '212b850', '2590905', '4a0187b', 'cfc7ff1', '54e3018', '1e8932f', '3488f26', '08473cf', 'acaf498',
'40aaf77', '6ef9471', 'dde68d8', '7275095', '3f224c9', '1f6bbde', '99bc12e', '0a69b62', 'e10c1fb', 'e3ea01d', 'c5a0891',
'1f86e9a', 'ee55d9e', 'b971da6', '28f34ab', '2caa419', '26d307a', '6b88ada', '4e893a4', '3236f62', 'c88640c', 'a00325a',
'6a66c54', '0b22b83', 'f0b9b67', 'a387799', '1cb2d60', '875879a', 'a008435', '3b448cb', '1d64dc7', 'd1a06c9', '1a69ef0',
'18f988a', '88d4e37', '36d2ecb', 'ee37d67', 'ece1cb0', 'f4a82a3', 'cf47a0e', '3334cb1', '08fde90', '16f03e0', '58668f1',
'0138da1', '12a1ff9', 'a457425', '7f10403', 'b29848b', '278e46a', '7412e27', '58d59b9', '16bc9c0', '694fa9c', 'df67757',
'bbcd6c5', '7575728', 'db91ac4', '5698505', '28c209e', '1b1295e', '94ff3cf', '3918f99', '81a0e12', '113282b', '828e277',
'f5af2b9', '09513ab', '3dc7b91', '3d83e00', '26b8dd7', '5572ba9', 'bb4c1a8', '81feea0', '9f74689', '5f1c9e4', '4b5cc95',
'ab1e6a7', '801acf8', '97b4698', 'e28f7d6', '4fe70a1', 'c288534', '2a8209f', 'bc87a2d', '8fbf991', '8382d02', 'e142459',
'0d210c0', '89de994', '9187046', '634a4d3', 'b6ee060', '61770e7', '599d6d2', '9d73672', 'e6ccef1', '2b84ade', 'd2ca39f',
'04a2fe9', '3c10d06', '4e145fd', '07ec556', '847fc70', '5ea346e', 'd42fb06', '32443f6', 'a5fc553', 'b465705', 'd04466f',
'be2cd69', '50b9123', '8b129ba', 'b527557');

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

security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);

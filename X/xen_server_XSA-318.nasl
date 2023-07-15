#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136189);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2020-11742");
  script_xref(name:"IAVB", value:"2020-B-0023-S");

  script_name(english:"Xen Bad Continuation Handling in GNTTABOP_copy DoS (XSA-318)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor installed on the remote host is affected by a denial
of service vulnerability in GNTTABOP_copy due to status fields of individual operations being left uninitialised. A
buggy or malicious guest can construct its grant table in such a way that, when a backend domain tries to copy a grant,
it hits the incorrect exit path. This returns success to the caller without doing anything, which may cause crashes or
other incorrect behaviour.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # http://xenbits.xen.org/xsa/advisory-318.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b9a6dd9");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch or workaround according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11742");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

fixes['4.9']['fixed_ver']           = '4.9.4';
fixes['4.9']['fixed_ver_display']   = '4.9.4 (changeset 45c9073)';
fixes['4.9']['affected_ver_regex']  = '^4\\.9\\.';
fixes['4.9']['affected_changesets'] = make_list(
'773686b', '4e79375', '8d26adc', 'b3718b7', 'cf2e9cc', '43ab30b', '55bd90d', '173e805', '248f22e', 'ec229c2',
'e879bfe', 'ce126c9', '4b69427', '8d1ee9f', 'e60b3a9', '25f5530', '49db55f', 'fa34ed5', '704f7ec', 'a930a74', 
'8c52ee2', '2e15a19', '70639ac', 'c3b479d', 'e349eae', '632fb4e', '4608c6d', '7daacca', '859e48e', '5be2dd0', 
'b0147bd', 'cadd66a', 'd3c4b60', 'd59f5c4', '44303c6', '79538ba', '80c3157', '73f1a55', 'bc20fb1', '754a531', 
'7b032c2', 'ff4fdf0', '8d2a688', 'b9013d7', 'bc8e5ec', '34907f5', 'e70bf7e', 'fa0b891', '3a8177c', '04ec835', 
'8d63ec4', '1ff6b4d', 'f092d86', 'e4b534f', '87c49fe', '19becb8', '43775c0', 'f6b0f33', 'a17e75c', '67530e7', 
'f804549', '84f81a8', '56aa239', '105db42', 'd9da3ea', 'ac90240', '3db28b0', '9b6f1c0', '0c4bbad', '917d8d3', 
'3384ea4', '352421f', '04e9dcb', '1612f15', 'f952b1d', '63d9330', 'f72414a', 'ac3a5f8', '1ae6b8e', '1dd3dcc', 
'7390fa1', '7e78dc4', '8fdfb1e', '55d36e2', '045f37c', 'dd7e637', '7a40b5b', 'f5acf97');

fixes['4.10']['fixed_ver']           = '4.10.4';
fixes['4.10']['fixed_ver_display']   = '4.10.4 (changeset 24d62e1)';
fixes['4.10']['affected_ver_regex']  = '^4\\.10\\.';
fixes['4.10']['affected_changesets'] = make_list(
'cbedabf', '38e589d', 'a91b8fc', '3e0c316', '49a5d6e', '6cb1cb9', 'ba2776a', '9d143e8', 'fe8dab3', '07e546e', 
'fefa5f9', 'c9f9ff7', '406d40d', 'e489955', '37139f1', 'fde09cb', '804ba02', 'e8c3971', 'a8c4293', 'aa40452',
'1da3dab', 'e5632c4', '902e72d', '6a14610', 'ea815b2', '13ad331', '61b75d9', 'e70e7bf', 'e966e2e', 'dfa16a1',
'a71e199', 'c98be9e', 'a548e10', 'd3c0e84', '53b1572', '7203f9a', '6d1659d', 'a782173', '24e90db', '0824bc6',
'e6f3135', '3131bf9');

fixes['4.11']['fixed_ver']           = '4.11.4';
fixes['4.11']['fixed_ver_display']   = '4.11.4-pre (changeset d353f82)';
fixes['4.11']['affected_ver_regex']  = '^4\\.11\\.';
fixes['4.11']['affected_changesets'] = make_list(
'52da389', 'd430e15', '7900cb7', '06a5a27', 'affb032', '5adb81a', '4b4ec47', '8f51dad', '09508fd', 'ac3b39c',
'480d9b4', 'dfcd120', '696d142', '6bc54c0', 'f9e2a60', '98cf186', 'a12c52d', '21fc266', '7224587', '2ffed5c', 
'8348cc7', 'a4f502e', '5abd261', 'b187c14', '8fa2976', '9e48faf', '888a7da', '06adda7', '346eae8', '0e126cc', 
'ddffc4d', '14b62ab', '6561994', 'f562c6b', 'd35cbee', '85e047d', 'd9dd863', '0e5be46', '146d5bd', '81bd09f', 
'b9527ec', 'd627249', 'd397a5a', '6a40067', 'a700446', '0d91d9d', '005c9b8', '1432cd5', '608be81', 'd81c711', 
'3d2cc67', 'd4a67be', 'b8a8278', '06555fd');

fixes['4.12']['fixed_ver']           = '4.12.3';
fixes['4.12']['fixed_ver_display']   = '4.12.3-pre (changeset 3536f8d)';
fixes['4.12']['affected_ver_regex']  = '^4\\.12\\.';
fixes['4.12']['affected_changesets'] = make_list(
'46bde05', '1541b26', '45624a7', 'dc3fb83', 'e8c8071', 'a46cd06', '524e739', '36f810b', '752558e', 'c1a1c4e',
'4c69d1c', '9a082e1', 'e282e87', 'f326440', '736c67b', '94f0bb7', '4c18745', '3c37292', '813757c', '824bdb4', 
'30acb65', '2d86de4', 'c03afae', '3d89e04', '95d956d', 'b165d13', '8663b6a', '636b40d', '16803a6', 'd32c575', 
'e4f4127', 'b9063ce', '58d3a68', 'a12589f', '5454111', '7ee6e17', '71382e9');

fixes['4.13']['fixed_ver']           = '4.13.1';
fixes['4.13']['fixed_ver_display']   = '4.13.1-pre (changeset b66ce50)';
fixes['4.13']['affected_ver_regex']  = '^4\\.13\\.';
fixes['4.13']['affected_changesets'] = make_list(
'd91d4fe', 'b6a2c42', 'ef922bd', '65b16f3', '736da59', '460003e', '2e05b8a', 'c0dad81', '436c54e', '181614a', 
'04497b3', 'ad5e611', 'b3e08a6', '71b7ead', 'd5be080', 'c7a1e58', '18d9129', '16670ad', '69c8307', 'e519573', 
'680356e', '6a5ebbb', 'e9fdf6a', 'ac75ea8', 'a99de9d', 'e1e24c5', '0d16bb7', '07ac8a9', '431ddeb', '5e10699', 
'655897c', 'a8fbb0f', 'd3f3e44', '1bfc29f', '86f0b73', '994ff51', 'c7409f8', 'fbb17c4', '80dd503', 'e6854fe', 
'9e779d1', '0518c16', 'ef5961d', '1482807', '8a717bd', 'c0d0b4e', 'c080e5b', '7f11b1c', '95d43cd', '328dd23', 
'e312149', '659efd4', '721f2c3', '3baeeed', '01acc25', 'fe0496e', '55ca8ab', 'cb071e4', 'efb9c68', '6a10d04', 
'492be8e', 'c1264bf');

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
security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);

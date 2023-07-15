#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134307);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/06");

  script_name(english:"Xen Arm-Based CPU Speculation past the ERET Instruction (XSA-312)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor installed on the remote host is affected by a
speculative memory accesses vulnerability. Some CPUs can speculate past an ERET instruction and potentially perform
speculative accesses to memory before processing the exception return. Since the register state is often controlled by
lower privilege level (i.e guest kernel/userspace) at the point of the ERET. An attacker, which could include a
malicious untrusted user process on a trusted guest, or an untrusted guest, may be able to use it as part of
side-channel attack to read host memory. System running all version of Xen are affected. An individual Arm-based CPU is
vulnerable depending on its speculation properties, while x86 systems are not vulnerable.");
  # https://xenbits.xen.org/xsa/advisory-312.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95d8cb1e");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch or workaround according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/06");

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

fixes['4.9']['fixed_ver']           = '4.9.4';
fixes['4.9']['fixed_ver_display']   = '4.9.4 (changeset cf2e9cc)';
fixes['4.9']['affected_ver_regex']  = '^4\\.9\\.';
fixes['4.9']['affected_changesets'] = make_list(
'43ab30b', '55bd90d', '173e805', '248f22e', 'ec229c2', 'e879bfe', 'ce126c9', '4b69427', '8d1ee9f', 'e60b3a9', '25f5530',
'49db55f', 'fa34ed5', '704f7ec', 'a930a74', '8c52ee2', '2e15a19', '70639ac', 'c3b479d', 'e349eae', '632fb4e', '4608c6d',
'7daacca', '859e48e', '5be2dd0', 'b0147bd', 'cadd66a', 'd3c4b60', 'd59f5c4', '44303c6', '79538ba', '80c3157', '73f1a55',
'bc20fb1', '754a531', '7b032c2', 'ff4fdf0', '8d2a688', 'b9013d7', 'bc8e5ec', '34907f5', 'e70bf7e', 'fa0b891', '3a8177c',
'04ec835', '8d63ec4', '1ff6b4d', 'f092d86', 'e4b534f', '87c49fe', '19becb8', '43775c0', 'f6b0f33', 'a17e75c', '67530e7',
'f804549', '84f81a8', '56aa239', '105db42', 'd9da3ea', 'ac90240', '3db28b0', '9b6f1c0', '0c4bbad', '917d8d3', '3384ea4',
'352421f', '04e9dcb', '1612f15', 'f952b1d', '63d9330', 'f72414a', 'ac3a5f8', '1ae6b8e', '1dd3dcc', '7390fa1', '7e78dc4',
'8fdfb1e', '55d36e2', '045f37c', 'dd7e637', '7a40b5b', 'f5acf97');

fixes['4.10']['fixed_ver']           = '4.10.4';
fixes['4.10']['fixed_ver_display']   = '4.10.4 (changeset 49a5d6e)';
fixes['4.10']['affected_ver_regex']  = '^4\\.10\\.';
fixes['4.10']['affected_changesets'] = make_list(
'6cb1cb9', 'ba2776a', '9d143e8', 'fe8dab3', '07e546e', 'fefa5f9', 'c9f9ff7', '406d40d', 'e489955', '37139f1', 'fde09cb',
'804ba02', 'e8c3971', 'a8c4293', 'aa40452', '1da3dab', 'e5632c4', '902e72d', '6a14610', 'ea815b2', '13ad331', '61b75d9',
'e70e7bf', 'e966e2e', 'dfa16a1', 'a71e199', 'c98be9e', 'a548e10', 'd3c0e84', '53b1572', '7203f9a', '6d1659d', 'a782173',
'24e90db', '0824bc6', 'e6f3135', '3131bf9');

fixes['4.11']['fixed_ver']           = '4.11.4';
fixes['4.11']['fixed_ver_display']   = '4.11.4-pre (changeset ddffc4d)';
fixes['4.11']['affected_ver_regex']  = '^4\\.11\\.';
fixes['4.11']['affected_changesets'] = make_list(
'14b62ab', '6561994', 'f562c6b', 'd35cbee', '85e047d', 'd9dd863', '0e5be46', '146d5bd', '81bd09f', 'b9527ec', 'd627249',
'd397a5a', '6a40067', 'a700446', '0d91d9d', '005c9b8', '1432cd5', '608be81', 'd81c711', '3d2cc67', 'd4a67be', 'b8a8278',
'06555fd');

fixes['4.12']['fixed_ver']           = '4.12.2';
fixes['4.12']['fixed_ver_display']   = '4.12.2 (changeset a5fcafb)';
fixes['4.12']['affected_ver_regex']  = '^4\\.12\\.';
fixes['4.12']['affected_changesets'] = make_list('8907110');

fixes['4.13']['fixed_ver']           = '4.13.1';
fixes['4.13']['fixed_ver_display']   = '4.13.1-pre (changeset efb9c68)';
fixes['4.13']['affected_ver_regex']  = '^4\\.13\\.';
fixes['4.13']['affected_changesets'] = make_list('6a10d04', '492be8e', 'c1264bf');

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

security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);

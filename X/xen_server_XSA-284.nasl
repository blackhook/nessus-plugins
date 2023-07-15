#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134165);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2019-17340");
  script_xref(name:"IAVB", value:"2019-B-0079-S");

  script_name(english:"Xen Grant Table Transfer Issues on Large Hosts Denial of Service Vulnerability (XSA-284)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor installed on the remote host is affected by a denial
of service vulnerability. When the code processing grant table transfer requests finds a page with an address too large 
to be represented in the interface with the guest, it allocates a replacement page and copies page contents. However,
the code doing so fails to set the newly allocated page's accounting properties correctly, resulting in the page
becoming not only unusable by the target domain, but also unfreeable upon domain cleanup. The page as well as certain
other remnants of an affected guest will be leaked. Furthermore, the internal state of the processing code was also not
updated correctly, resulting in the insertion of an IOMMU mapping to the page being replaced (and subsequently freed),
allowing the domain access to memory it does not own. The primary impact is a memory leak. Malicious or buggy guests
with passed through PCI devices may also be able to escalate their privileges, crash the host, or access data belonging
to other guests.");
  # https://xenbits.xen.org/xsa/advisory-284.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9674a20");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch or workaround according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17340");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

fixes['4.7']['fixed_ver']           = '4.7.6';
fixes['4.7']['fixed_ver_display']   = '4.7.6 (changeset eeea811)';
fixes['4.7']['affected_ver_regex']  = '^4\\.7\\.';
fixes['4.7']['affected_changesets'] = make_list(
'710cc09', 'ab6d56c', '4f3858f', '045d4f7', '2b3463f', 'efe21ad', '9c82759', '3d3e474', '4e69e43', '3d33cc6', '3f7b4ec',
'7ba1c7d', '87d5aa4', '9b8375a', 'da93914', '0aa4696', 'f05a33e', 'f440b31', '1a90803', '0abc1ae', '1fdb25a', 'c9641d4',
'61c4360', 'df66c1c', '59732fd', '3f7fd2b', 'bcbd8b9', 'dfee811', '95ff4e1', 'ded2a37', '87dba80', 'fe028e6', 'a51e6a3',
'0e66281', '51d9780', '91ca84c', 'bce2dd6', 'fa807e2', '97aff08', 'e90e243', 'c0e854b', '9858a1f', 'a404136', 'dc111e9',
'0873699', '280a556');

fixes['4.8']['fixed_ver']           = '4.8.5';
fixes['4.8']['fixed_ver_display']   = '4.8.5 (changeset b9b0c46)';
fixes['4.8']['affected_ver_regex']  = '^4\\.8\\.';
fixes['4.8']['affected_changesets'] = make_list('908e768');

fixes['4.9']['fixed_ver']           = '4.9.4';
fixes['4.9']['fixed_ver_display']   = '4.9.4 (changeset 7a40b5b)';
fixes['4.9']['affected_ver_regex']  = '^4\\.9\\.';
fixes['4.9']['affected_changesets'] = make_list('f5acf97');

fixes['4.10']['fixed_ver']           = '4.10.4';
fixes['4.10']['fixed_ver_display']   = '4.10.4-pre (changeset edbc9b0)';
fixes['4.10']['affected_ver_regex']  = '^4\\.10\\.';
fixes['4.10']['affected_changesets'] = make_list('edb80d2');

fixes['4.11']['fixed_ver']           = '4.11.2';
fixes['4.11']['fixed_ver_display']   = '4.11.2-pre (changeset 1028304)';
fixes['4.11']['affected_ver_regex']  = '^4\\.11\\.';
fixes['4.11']['affected_changesets'] = make_list(
'87f51bf', 'dd492b8', 'e2e3a1d', '850ca94', '514dccd', 'e202feb', '1986728', '2cd833d', 'de09411', 'dd914e4', '63d7113',
'af25f52', '91f2ad7', '0b2be0b', '7d1bd98', 'd8b2418', 'bf608fd');

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

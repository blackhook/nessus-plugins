#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119658);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2018-19964");
  script_bugtraq_id(106182);
  script_xref(name:"IAVB", value:"2018-B-0149-S");

  script_name(english:"Xen Project Guest p2m Page Removal Error Handling DoS (XSA-277)");
  script_summary(english:"Checks 'xl info' output for the Xen hypervisor version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor
installed on the remote host is affected by a guest-to-host denial of
service vulnerability. An attacker located on a guest virtual machine
may be able to exploit this vulnerability to affect the availability
of the host system. Only x86 systems running untrusted HVM or PVH
guests are considered vulnerable.

Note that Nessus has checked the changeset versions based on the
xen.git change log. Nessus did not check guest hardware configurations
or if patches were applied manually to the source code before a
recompile and reinstall.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-277.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/gitweb/?p=xen.git;a=summary");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19964");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/13");

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

fixes['4.11']['fixed_ver']           = '4.11.1';
fixes['4.11']['fixed_ver_display']   = '4.11.1-pre (changeset eb6830a)';
fixes['4.11']['affected_ver_regex']  = '^4\\.11\\.';
fixes['4.11']['affected_changesets'] = make_list("b88ccb3", "3b2a779",
  "946f345", "086a9dd", "dea9fc0", "ff9f873", "0f0ad14", "8ad462a",
  "d67b849", "8f3f58c", "06a50b0", "fe10c22", "e243639", "f0b4b69",
  "d34471f", "26feeb5", "221acbf", "8bed728", "18b5947", "94fba9f",
  "33664f9", "a2e35a7", "451f9c8", "d7cbb4b", "bb6d070", "b1a47ef",
  "5b1592d", "0719a5f", "03fd745", "d1caf6e", "a07f444", "74fee1b",
  "2004a91", "8c8b3cb", "5acdd26", "733450b", "d757c29", "6c7d074",
  "2a47c75", "007752f", "fb78137", "665e768", "f4a049e", "02d2c66",
  "57483c0", "d044f6c", "e6441a8", "48fb482", "fa79f9e", "1d32c21",
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

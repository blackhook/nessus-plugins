#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122871);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2019-17342");

  script_name(english:"Xen Project steal_page Race Condition Multiple Vulnerabilities (XSA-287)");
  script_summary(english:"Checks 'xl info' output for the Xen hypervisor version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor
installed on the remote host is affected by multiple vulnerabilities
including denial of service, information disclosure, and privilege
escalation due to a steal_page race condition. Only x86 systems are
affected.

Note that Nessus has checked the changeset versions based on the
xen.git change log. Nessus did not check guest hardware configurations
or if patches were applied manually to the source code before a
recompile and reinstall.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-287.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/gitweb/?p=xen.git;a=summary");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17342");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

fixes['4.7']['fixed_ver']           = '4.7.6';
fixes['4.7']['fixed_ver_display']   = '4.7.6 (changeset a1500d4)';
fixes['4.7']['affected_ver_regex']  = '^4\\.7\\.';
fixes['4.7']['affected_changesets'] = make_list("362cca8", "eeea811",
  "710cc09", "ab6d56c", "4f3858f", "045d4f7", "2b3463f", "efe21ad",
  "9c82759", "3d3e474", "4e69e43", "3d33cc6", "3f7b4ec", "7ba1c7d",
  "87d5aa4", "9b8375a", "da93914", "0aa4696", "f05a33e", "f440b31",
  "1a90803", "0abc1ae", "1fdb25a", "c9641d4", "61c4360", "df66c1c",
  "59732fd", "3f7fd2b", "bcbd8b9", "dfee811", "95ff4e1", "ded2a37",
  "87dba80", "fe028e6", "a51e6a3", "0e66281", "51d9780", "91ca84c",
  "bce2dd6", "fa807e2", "97aff08", "e90e243", "c0e854b", "9858a1f",
  "a404136", "dc111e9", "0873699", "280a556");

fixes['4.10']['fixed_ver']           = '4.10.4';
fixes['4.10']['fixed_ver_display']   = '4.10.4-pre (changeset dfc7e3c)';
fixes['4.10']['affected_ver_regex']  = '^4\\.10\\.';
fixes['4.10']['affected_changesets'] = make_list("382e4a6", "edbc9b0",
  "edb80d2");

fixes['4.11']['fixed_ver']           = '4.11.2';
fixes['4.11']['fixed_ver_display']   = '4.11.2-pre (changeset 4298abd)';
fixes['4.11']['affected_ver_regex']  = '^4\\.11\\.';
fixes['4.11']['affected_changesets'] = make_list("4f785ea", "1028304",
  "87f51bf", "dd492b8", "e2e3a1d", "850ca94", "514dccd", "e202feb",
  "1986728", "2cd833d", "de09411", "dd914e4", "63d7113", "af25f52",
  "91f2ad7", "0b2be0b", "7d1bd98", "d8b2418", "bf608fd");

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

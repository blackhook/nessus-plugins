#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105492);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2017-17564");
  script_xref(name:"IAVB", value:"2018-B-0007-S");

  script_name(english:"Xen Shadow Mode Page Use Reference Counting Error Handling Guest-to-Host DoS (XSA-250)");
  script_summary(english:"Checks 'xl info' output for the Xen hypervisor version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor
installed on the remote host is affected by a guest-to-host denial
of service vulnerability.

Note that x86 systems are vulnerable. ARM systems are not vulnerable.

Note that Nessus has checked the changeset versions based on the
xen.git change log. Nessus did not check guest hardware configurations
or if patches were applied manually to the source code before a
recompile and reinstall.");
  script_set_attribute(attribute:"see_also", value:"http://xenbits.xen.org/xsa/advisory-250.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/gitweb/?p=xen.git;a=summary");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-17564");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

fixes['4.5']['fixed_ver']           = '4.5.5';
fixes['4.5']['fixed_ver_display']   = '4.5.5 (changeset 7e02b65)';
fixes['4.5']['affected_ver_regex']  = '^4\\.5\\.';
fixes['4.5']['affected_changesets'] = make_list("c8fad5e", "ab5ca36",
  "94a81c5", "ea1620f", "ca708d3", "d144bda", "41f6dd0", "b0be3c2",
  "42ea1dc", "08aa260", "03b06d3", "77666b6", "bbeb763", "5fdf16f",
  "0e9967d", "da4f24d", "b7582ac", "196371c", "7afc8ad", "72c107b",
  "5659aa5", "a224de6", "6442fa9", "db487a6", "709230f", "83724d9",
  "04b8c4c", "0b2ceae", "e3f0768", "d5a5231", "c5b0fe5", "136ff4e",
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
fixes['4.6']['fixed_ver_display']   = '4.6.6 (changeset 45ddc4e)';
fixes['4.6']['affected_ver_regex']  = '^4\\.6\\.';
fixes['4.6']['affected_changesets'] = make_list("1ca93b7", "8c0c36e",
  "6e43623", "47d3e73", "ea80245", "37bb22b", "9b0c2a2", "8d3fe28",
  "be63d66", "9454e30", "aad5a67", "d8b0ebf", "f0208a4", "42b2c82",
  "57318e1", "9f22d72", "e0353b4", "76f1549", "9bac910", "c7a43e3",
  "913d4f8", "c5881c5", "b0239cd", "78fd0c3", "9079e0d", "1658a87",
  "22b6dfa", "a8cd231", "629eddd", "64c03bb", "b4660b4", "1ac8162",
  "747df3c", "5ae011e", "f974d32", "3300ad3", "d708b69");

fixes['4.7']['fixed_ver']           = '4.7.5';
fixes['4.7']['fixed_ver_display']   = '4.7.5-pre (changeset b9c150e)';
fixes['4.7']['affected_ver_regex']  = '^4\\.7\\.';
fixes['4.7']['affected_changesets'] = make_list("5a99156", "4f34d9f",
  "4133de7", "b3981ea", "184f259", "67966a9", "af3f585");

fixes['4.8']['fixed_ver']           = '4.8.3';
fixes['4.8']['fixed_ver_display']   = '4.8.3-pre (changeset 68db694)';
fixes['4.8']['affected_ver_regex']  = '^4\\.8\\.';
fixes['4.8']['affected_changesets'] = make_list("5069fdd", "a66b814",
  "d60d469", "e54bc7e", "fcc60bc", "60e86f3", "9ba6783", "bc244b7",
  "13eb73f", "6183d53", "1ac3ab7", "e1fa1c6", "96e76d8", "651d839",
  "14826e3", "814e065", "03af24c", "4a3c5e1", "2956a3f", "3cd9d84",
  "ffb2947", "f457a22", "011a612", "5b37b5c", "379213c", "f3b2080",
  "fcbbd0f", "0c647de", "bdc2ae6", "96e6364", "1a8ad09", "df89197",
  "c4f969d", "b1f3f1d", "7251c06", "1960ca8", "866cfa1", "ddd6e41",
  "370cc9a", "39e3024", "9f092f5", "667f70e", "2116fec", "1a535c3",
  "ee3fc24", "d623d82", "dda458c", "c642b12", "80d7ef3", "ff4f60a",
  "36898eb", "4d7ccae", "e574046", "90dafa4", "c020cf2");

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

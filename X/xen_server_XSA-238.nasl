#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103973);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id(
    "CVE-2017-15588",
    "CVE-2017-15589",
    "CVE-2017-15590",
    "CVE-2017-15591",
    "CVE-2017-15592",
    "CVE-2017-15593",
    "CVE-2017-15594",
    "CVE-2017-15595",
    "CVE-2017-15596"
  );
  script_bugtraq_id(101490, 101496, 101500);
  script_xref(name:"IAVB", value:"2017-B-0142-S");

  script_name(english:"Xen Hypervisor Multiple Functions DMOP Handling Guest-to-Host DoS (XSA-238)");
  script_summary(english:"Checks 'xl info' output for the Xen hypervisor version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor
installed on the remote host is affected by unspecified flaws in
arch/x86/hvm/ioreq.c that is triggered when handling DMOPs. This may
allow an attacker within a  guest to consume excessive resources.

Note this can only be exploited by domains controlling HVM guests.

Note that Nessus has checked the changeset versions based on the
xen.git change log. Nessus did not check guest hardware configurations
or if patches were applied manually to the source code before a
recompile and reinstall.");
  script_set_attribute(attribute:"see_also", value:"http://xenbits.xen.org/xsa/advisory-238.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/gitweb/?p=xen.git;a=summary");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15595");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/19");

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

# XSA-238
fixes['4.5']['fixed_ver']           = '4.5.5';
fixes['4.5']['fixed_ver_display']   = '4.5.5 (changeset 196371c)';
fixes['4.5']['affected_ver_regex']  = '^4\\.5\\.';
fixes['4.5']['affected_changesets'] = make_list("7afc8ad", "72c107b",
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
fixes['4.6']['fixed_ver_display']   = '4.6.6 (changeset 76f1549)';
fixes['4.6']['affected_ver_regex']  = '^4\\.6\\.';
fixes['4.6']['affected_changesets'] = make_list("9bac910", "c7a43e3",
  "913d4f8", "c5881c5", "b0239cd", "78fd0c3", "9079e0d", "1658a87",
  "22b6dfa", "a8cd231", "629eddd", "64c03bb", "b4660b4", "1ac8162",
  "747df3c", "5ae011e", "f974d32", "3300ad3", "d708b69");

fixes['4.7']['fixed_ver']           = '4.7.4';
fixes['4.7']['fixed_ver_display']   = '4.7.4-pre (changeset e61be54)';
fixes['4.7']['affected_ver_regex']  = '^4\\.7\\.';
fixes['4.7']['affected_changesets'] = make_list("e3f7a64", "957ad23",
  "b1ae705", "3add76f", "314a8fc", "d6aad63", "7c99633", "145c18d",
  "c3fa5cd", "487f8f9", "ffcfc40", "c7783d9", "3331050", "83966a3",
  "a67b223", "68dbba2", "2728470", "dea68ed", "9d12253", "73d7bc5",
  "b704b1a", "ca4ef7b", "ece330a", "3d63ebc", "30d50f8", "2dc3cdb",
  "5151257", "c9f3ca0", "e873251", "8aebf85", "c362cde", "fece08a");

fixes['4.8']['fixed_ver']           = '4.8.3';
fixes['4.8']['fixed_ver_display']   = '4.8.3-pre (changeset 7251c06)';
fixes['4.8']['affected_ver_regex']  = '^4\\.8\\.';
fixes['4.8']['affected_changesets'] = make_list("1960ca8", "866cfa1",
  "ddd6e41", "370cc9a", "39e3024", "9f092f5", "667f70e", "2116fec",
  "1a535c3", "ee3fc24", "d623d82", "dda458c", "c642b12", "80d7ef3",
  "ff4f60a", "36898eb", "4d7ccae", "e574046", "90dafa4", "c020cf2");

fixes['4.9']['fixed_ver']           = '4.9.1';
fixes['4.9']['fixed_ver_display']   = '4.9.1-pre (changeset ef61bcf)';
fixes['4.9']['affected_ver_regex']  = '^4\\.9\\.';
fixes['4.9']['affected_changesets'] = make_list("44ceb19", "ae45442",
  "784afd9", "22032b2", "58da67f", "d1b64cc", "9cde7a8", "1cdcb36",
  "84c039e", "b244ac9", "612044a", "e8fd372", "a568e25", "8fef83e",
  "478e40c", "22ea731", "e7703a2", "91ded3b", "2cc3d32", "79775f5",
  "43cb0c4", "4821228", "d23bcc5", "308654c", "6fd84b3", "89b36cc",
  "a9ecd60", "798f6c9", "6508278", "5587d9a", "527fc5c", "5ff1de3",
  "692ed82", "9bf14bb", "c57b1f9", "6b147fd", "0e186e3", "afc5ebf",
  "266fc0e", "4698106", "f4f02f1", "0fada05", "ab4eb6c", "b29ecc7",
  "a11d14b", "107401e", "1b7834a");

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

security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);

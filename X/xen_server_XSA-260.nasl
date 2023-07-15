#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109727);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-8897");
  script_bugtraq_id(104071);

  script_name(english:"Xen Intel Architecture Debug Exception Handling Local Privilege Escalation (XSA-260)");
  script_summary(english:"Checks 'xl info' output for the Xen hypervisor version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor
installed on the remote host is affected by a local privilege 
escalation vulnerability.

Note that Nessus has checked the changeset versions based on the
xen.git change log. Nessus did not check guest hardware configurations
or if patches were applied manually to the source code before a
recompile and reinstall.");
  script_set_attribute(attribute:"see_also", value:"http://xenbits.xen.org/xsa/advisory-260.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/gitweb/?p=xen.git;a=summary");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8897");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows POP/MOV SS Local Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

fixes['4.6']['fixed_ver']           = '4.6.6';
fixes['4.6']['fixed_ver_display']   = '4.6.6 (changeset 3b96676)';
fixes['4.6']['affected_ver_regex']  = '^4\\.6\\.';
fixes['4.6']['affected_changesets'] = make_list("2f3cde3", "acd8661",
  "5ddc3f8", "927aca7", "b4b553d", "b766574", "10898d7", "0b38930",
  "33f70b8", "cf03d32", "525c381", "4c1e2d3", "021009e", "4972c38",
  "bd461fc", "c9c1bb6", "0fbf30a", "7e20b9b", "d1618f4", "9d534c1",
  "dbb3553", "e54a8c6", "8005ed3", "9a852e0", "d779cc1", "c93bcf9",
  "15adcf3", "d7b8190", "2b1457f", "a357880", "ee23fcc", "5651015",
  "225e9c7", "3c70619", "1222333", "75bdd69", "8994cf3", "642c603",
  "c25ea9a", "feba571", "0163087", "44c2666", "db743b0", "41a5cce",
  "4e1b9e9", "4d21549", "ff4800c", "2613a1b", "8335c8a", "ab20c5c",
  "9089da9", "8edfc82", "af5b61a", "ec05090", "75263f7", "f7e273a",
  "03c7d2c", "9ce1a71", "a735c7a", "44ad7f6", "91dc902", "a065841",
  "c6e9e60", "f94c11d", "45ddc4e", "1ca93b7", "8c0c36e", "6e43623",
  "47d3e73", "ea80245", "37bb22b", "9b0c2a2", "8d3fe28", "be63d66",
  "9454e30", "aad5a67", "d8b0ebf", "f0208a4", "42b2c82", "57318e1",
  "9f22d72", "e0353b4", "76f1549", "9bac910", "c7a43e3", "913d4f8",
  "c5881c5", "b0239cd", "78fd0c3", "9079e0d", "1658a87", "22b6dfa",
  "a8cd231", "629eddd", "64c03bb", "b4660b4", "1ac8162", "747df3c",
  "5ae011e", "f974d32", "3300ad3", "d708b69");

fixes['4.7']['fixed_ver']           = '4.7.5';
fixes['4.7']['fixed_ver_display']   = '4.7.5 (changeset a6a2b5a)';
fixes['4.7']['affected_ver_regex']  = '^4\\.7\\.';
fixes['4.7']['affected_changesets'] = make_list("54ff338", "1bd5a36",
  "5fc0102", "a8ef075", "e613050", "2fbc006", "1619cff", "5c81317",
  "912aa9b", "63b140f", "62b1879", "9680710", "dca80ab");

fixes['4.8']['fixed_ver']           = '4.8.4';
fixes['4.8']['fixed_ver_display']   = '4.8.4-pre (changeset 3f59d0b)';
fixes['4.8']['affected_ver_regex']  = '^4\\.8\\.';
fixes['4.8']['affected_changesets'] = make_list("a89390b", "40c4ab8",
  "90676b7", "1052a21", "a2f02df", "501718a", "957ff30", "1e9ac23",
  "95befc6", "372583c", "202aaf8", "e4e9632", "a753be1", "8f9846f",
  "0864795", "866deda", "c67e19f", "bc6414f", "883c8db", "7db1c43",
  "813fe21", "3cadc8b", "f7bf4d2", "14217cb", "ce185fb", "a2700ca",
  "b19b206", "a442d40", "1901f62", "1581910", "15f57b8", "7ef31c0",
  "bc8aa42", "30a153d", "da92664", "6b08396", "f6ae9c0", "ad9ddc3",
  "22d2146", "f9adc12", "e27fd5c", "03f9474", "c31070f", "1093876",
  "141be84", "bb49733", "48faa50", "5938aa1", "d11783c", "8e1e3c7",
  "99ed786", "76bdfe8", "fee4689", "c0bfde6", "64c1742", "8615385",
  "e09a5c2", "ff570a3", "e6bcb41", "29e7171", "c3d195c", "2cd189e",
  "afdad6a", "532ccf4", "da49e51", "ca9583d", "479b879", "2eefd92",
  "60c50f2", "1838e21", "5732a8e", "987b08d", "eadcd83", "ef2464c",
  "17bfbc8", "499391b", "87cb0e2", "393de92");

fixes['4.9']['fixed_ver']           = '4.9.3';
fixes['4.9']['fixed_ver_display']   = '4.9.3-pre (changeset b9b5a03)';
fixes['4.9']['affected_ver_regex']  = '^4\\.9\\.';
fixes['4.9']['affected_changesets'] = make_list("35a71c6", "b844573",
  "48dd543", "7866e11", "db7accf", "921bff4", "c147505", "dc527ff",
  "781e23a", "72ca580", "47d41f6", "7a59015", "259bee9", "6d4c4f0", "3e010f5");

fixes['4.10']['fixed_ver']           = '4.10.1';
fixes['4.10']['fixed_ver_display']   = '4.10.1 (changeset 07b6f42)';
fixes['4.10']['affected_ver_regex']  = '^4\\.10\\.';
fixes['4.10']['affected_changesets'] = make_list("373d496", "9abae6f",
  "abe5fb9", "99e5000");

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

security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);

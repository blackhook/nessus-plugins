#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(89680);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id(
    "CVE-2010-0296",
    "CVE-2010-1083",
    "CVE-2010-1323",
    "CVE-2010-2492",
    "CVE-2010-2798",
    "CVE-2010-2938",
    "CVE-2010-2942",
    "CVE-2010-2943",
    "CVE-2010-3015",
    "CVE-2010-3066",
    "CVE-2010-3067",
    "CVE-2010-3078",
    "CVE-2010-3086",
    "CVE-2010-3296",
    "CVE-2010-3432",
    "CVE-2010-3442",
    "CVE-2010-3477",
    "CVE-2010-3699",
    "CVE-2010-3858",
    "CVE-2010-3859",
    "CVE-2010-3865",
    "CVE-2010-3876",
    "CVE-2010-3877",
    "CVE-2010-3880",
    "CVE-2010-3904",
    "CVE-2010-4072",
    "CVE-2010-4073",
    "CVE-2010-4075",
    "CVE-2010-4080",
    "CVE-2010-4081",
    "CVE-2010-4083",
    "CVE-2010-4157",
    "CVE-2010-4158",
    "CVE-2010-4161",
    "CVE-2010-4238",
    "CVE-2010-4242",
    "CVE-2010-4243",
    "CVE-2010-4247",
    "CVE-2010-4248",
    "CVE-2010-4249",
    "CVE-2010-4251",
    "CVE-2010-4255",
    "CVE-2010-4263",
    "CVE-2010-4343",
    "CVE-2010-4346",
    "CVE-2010-4526",
    "CVE-2010-4655",
    "CVE-2011-0281",
    "CVE-2011-0282",
    "CVE-2011-0521",
    "CVE-2011-0536",
    "CVE-2011-0710",
    "CVE-2011-1010",
    "CVE-2011-1071",
    "CVE-2011-1090",
    "CVE-2011-1095",
    "CVE-2011-1478",
    "CVE-2011-1494",
    "CVE-2011-1495",
    "CVE-2011-1658",
    "CVE-2011-1659"
  );
  script_bugtraq_id(
    39042,
    42124,
    42237,
    42477,
    42527,
    42529,
    43022,
    43221,
    43353,
    43480,
    43578,
    43787,
    43806,
    43809,
    44219,
    44301,
    44354,
    44549,
    44630,
    44648,
    44665,
    44754,
    44755,
    44758,
    45004,
    45014,
    45028,
    45029,
    45037,
    45039,
    45054,
    45058,
    45063,
    45064,
    45073,
    45099,
    45118,
    45208,
    45262,
    45323,
    45661,
    45795,
    45972,
    45986,
    46265,
    46271,
    46421,
    46492,
    46563,
    46637,
    46766,
    47056,
    47185,
    47370
  );
  script_xref(name:"VMSA", value:"2011-0012");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/02");

  script_name(english:"VMware ESX / ESXi Third-Party Libraries Multiple Vulnerabilities (VMSA-2011-0012) (remote check)");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESX / ESXi host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX / ESXi host is missing a security-related patch.
It is, therefore, affected by multiple vulnerabilities in several
third-party components and libraries :

  - Kernel
  - krb5
  - glibc
  - mtp2sas
  - mptsas
  - mptspi");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2011-0012");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2012/000164.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX version 3.5 / 4.0 / 4.1 or ESXi version 3.5 / 4.0 /
4.1 / 5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2010-2943");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Reliable Datagram Sockets (RDS) rds_page_copy_user Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");
  script_require_ports("Host/VMware/vsphere");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("Host/VMware/version");
rel = get_kb_item_or_exit("Host/VMware/release");
port = get_kb_item_or_exit("Host/VMware/vsphere");
esx = '';

if ("ESX" >!< rel)
  audit(AUDIT_OS_NOT, "VMware ESX/ESXi");

extract = eregmatch(pattern:"^(ESXi?) (\d\.\d).*$", string:ver);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_APP_VER, "VMware ESX/ESXi");
else
{
  esx = extract[1];
  ver = extract[2];
}

# fixed build numbers are the same for ESX and ESXi
fixes = make_array(
          "3.5", "604481",
          "4.0", "480973",
          "4.1", "502767",
          "5.0", "515841"
        );

fix = FALSE;
fix = fixes[ver];

# get the build before checking the fix for the most complete audit trail
extract = eregmatch(pattern:'^VMware ESXi?.* build-([0-9]+)$', string:rel);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_BUILD, "VMware " + esx, ver);

build = int(extract[1]);

# if there is no fix in the array, fix is FALSE
if (!fix)
  audit(AUDIT_INST_VER_NOT_VULN, "VMware " + esx, ver, build);

if (build < fix)
{

  report = '\n  Version         : ' + esx + " " + ver +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fix +
           '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "VMware " + esx, ver, build);

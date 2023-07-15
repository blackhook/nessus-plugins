#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(89663);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/29");

  script_cve_id(
    "CVE-2012-1531",
    "CVE-2012-1532",
    "CVE-2012-1533",
    "CVE-2012-2110",
    "CVE-2012-3143",
    "CVE-2012-3159",
    "CVE-2012-3216",
    "CVE-2012-4416",
    "CVE-2012-5067",
    "CVE-2012-5068",
    "CVE-2012-5069",
    "CVE-2012-5070",
    "CVE-2012-5071",
    "CVE-2012-5072",
    "CVE-2012-5073",
    "CVE-2012-5074",
    "CVE-2012-5075",
    "CVE-2012-5076",
    "CVE-2012-5077",
    "CVE-2012-5078",
    "CVE-2012-5079",
    "CVE-2012-5080",
    "CVE-2012-5081",
    "CVE-2012-5082",
    "CVE-2012-5083",
    "CVE-2012-5084",
    "CVE-2012-5085",
    "CVE-2012-5086",
    "CVE-2012-5087",
    "CVE-2012-5088",
    "CVE-2012-5089",
    "CVE-2013-1659"
  );
  script_bugtraq_id(
    53158,
    55501,
    56025,
    56033,
    56039,
    56043,
    56046,
    56051,
    56054,
    56055,
    56056,
    56057,
    56058,
    56059,
    56061,
    56063,
    56065,
    56066,
    56067,
    56068,
    56070,
    56071,
    56072,
    56075,
    56076,
    56078,
    56079,
    56080,
    56081,
    56082,
    56083,
    58115
  );
  script_xref(name:"VMSA", value:"2013-0003");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/18");

  script_name(english:"VMware ESX / ESXi NFC and Third-Party Libraries Multiple Vulnerabilities (VMSA-2013-0003) (remote check)");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESX / ESXi host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX / ESXi host is missing a security-related patch.
It is, therefore, affected by multiple vulnerabilities, including
remote code execution vulnerabilities, in several components and
third-party libraries :

  - Java Runtime Environment (JRE)
  - Network File Copy (NFC) Protocol
  - OpenSSL");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2013-0003.html");
  # http://www.oracle.com/technetwork/topics/security/javacpuoct2012-1515924.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b0eb44d4");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX version 3.5 / 4.0 / 4.1 or ESXi version 3.5 / 4.0 /
4.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5088");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Method Handle Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");
  script_require_ports("Host/VMware/vsphere");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit("Host/VMware/version");
rel   = get_kb_item_or_exit("Host/VMware/release");
port  = get_kb_item_or_exit("Host/VMware/vsphere");
esx   = '';
build = 0;
fix   = FALSE;

if ("ESX" >!< rel)
  audit(AUDIT_OS_NOT, "VMware ESX/ESXi");

extract = eregmatch(pattern:"^(ESXi?) (\d\.\d).*$", string:ver);
if (empty_or_null(extract))
  audit(AUDIT_UNKNOWN_APP_VER, "VMware ESX/ESXi");

esx = extract[1];
ver = extract[2];

extract = eregmatch(pattern:'^VMware ESXi?.* build-([0-9]+)$', string:rel);
if (isnull(extract))
  audit(AUDIT_UNKNOWN_BUILD, "VMware " + esx, ver);

build = int(extract[1]);

fixes = make_array(
    "4.1", 874690,
    "4.0", 989856,
    "3.5", 988599
);

fix = fixes[ver];

if (!fix)
  audit(AUDIT_INST_VER_NOT_VULN, esx, ver, build);

if (build < fix)
{
  report = '\n  Version         : ' + esx + " " + ver +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fix +
           '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
  exit(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "VMware " + esx, ver, build);

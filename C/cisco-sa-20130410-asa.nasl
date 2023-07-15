#TRUSTED 74e8c5cade7c2f067632a5d247328c63eab45d20da7430c1b6b5d4ed7e963b1ce8c18e04f12b5e4e7ca3f9c8795e99c82bbe2a8f3a4720eeffca2df3dd921e85ed09a7be54afb6e5f201c8d8b2160cd47ad92418afd4bcb4feec6bc2e30f3a05be382f7120c83aa8916498cf52bd298e59ba618c40148f248e9195a033531d7ecd444bb8ef148b0b505feca6ae78f25ca26139a693aaf3e6d747b1f8c438be36bced30d7c72818809c2ab5f0cab2c2acda4d3f5652633c9bed689e105b1b8c3186776d64c0eaa664ade9cc96df724320db395643b829bc9bb71692c98e8c536a682fba5961c65002d4de49528595e478b3c9eae74755600bc866453b6ab6a00208cd92547e2af328bd9cd774288b37f1b6e4c333387745ee3fd701a808887f08bb8dc9c19f1d7e0992a772ea77f4a3b5305c28ea9ddb25496b73a2fefcdcd758b3569a0cb6a2f16cb7fac44829f3c518eeb40847517e6da3c42283d8433dbe8e651ab4f6802a1630e5edd2c68e601e9de07cf3ec6ff632ef57562a48ee7f7118c18efd379c807119e9f4ac2fb564914a95aa2051c4759fc58212fdb4e68fba801d3bf15dd8d93feb59de221ca41d0084a8e93b7442a42471840373e25adf77564eaf97f3ffff1b6356cf82b1d4d889aeceefe38d9eedd70fade8f8c2d3b56253ee798ddded86e2fb8c18b7f91aed663e80d09d25aead84f853cf73205211b0ce
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65931);
  script_version("1.14");
  script_cvs_date("Date: 2019/11/27");

  script_cve_id(
    "CVE-2013-1149",
    "CVE-2013-1150",
    "CVE-2013-1151",
    "CVE-2013-1152"
  );
  script_bugtraq_id(
    59001,
    59004,
    59005,
    59012
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCub85692");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuc72408");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuc80080");
  script_xref(name:"CISCO-BUG-ID", value:"CSCud16590");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130410-asa");

  script_name(english:"Cisco ASA Multiple Vulnerabilities (cisco-sa-20130410-asa)");
  script_summary(english:"Check ASA model and version");

  script_set_attribute(attribute:"synopsis", value:
"The remote security device is missing a vendor-supplied security
patch.");
  script_set_attribute(attribute:"description", value:
"The remote host (Cisco ASA 5500 series or 1000V Cloud Firewall) is
missing a security patch.  It, therefore, could be affected by the
following issues :

  - An unspecified vulnerability in the IKE version 1
    implementation. (CVE-2013-1149)

  - An unspecified vulnerability in the URL processing code
    of the authentication proxy feature. (CVE-2013-1150)

  - An unspecified vulnerability in the implementation to
    validate digital certificates. (CVE-2013-1151)

  - An unspecified vulnerability in the DNS inspection
    engine. (CVE-2013-1152)

A remote, unauthenticated attacker could exploit any of these
vulnerabilities to cause a device reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130410-asa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?999a3389");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130410-asa.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');
ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (model !~ '^55[0-9][0-9]' || model != '1000V' || model !~ '^65[0-9][0-9]' || model !~ '^76[0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'ASA 5500 6500 7600 or 1000V series');

# perform 3 checks against the system, if one if vuln - flag the asset

dos_chk = cisco_command_kb_item(
  "Host/Cisco/Config/show_crypto_ca_certificate",
  "show crypto ca certificates"
);

aaa_chk = cisco_command_kb_item(
  "Host/Cisco/Config/aaa_authentication_listener",
  "aaa authentication listener"
);

dns_chk = cisco_command_kb_item(
  "Host/Cisco/Config/service-policy_dns",
  "show service-policy | include dns"
);

flag = 0;


if (check_cisco_result(dos_chk) || check_cisco_result(aaa_chk) || check_cisco_result(dns_chk))
{
  if (
      preg(pattern:"Associated Trustpoints:", multiline:TRUE, string:dos_chk) 
       || !empty_or_null(aaa_chk) 
       || preg(pattern:"Inspect:", multiline:TRUE, string:dns_chk)
     ) 
  { 
   flag = 1; 
  }
}


# for 7.0 and 7.1 the recommendation is to migrate to 7.2 and upgrade
if ((ver =~ '^7\\.0($|[^0-9])' || ver =~ '^7\\.1($|[^0-9])') && flag )
{
  report =
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : migrate to 7.2.x (7.2(5.10) or later)\n';
  security_hole(port:0, extra:report);
  exit(0);
}

# for 8.1 the recommendation is to migrate to 8.2 and upgrade
if ((ver =~ '^8\\.1($|[^0-9])') && flag )
{
  report =
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : migrate to 8.2.x (8.2(5.38) or later)\n';
  security_hole(port:0, extra:report);
  exit(0);
}

# for 8.5 the recommended fix for CSCud16590 is to migrate to 9.x and upgrade
if ((ver =~ '^8\\.5($|[^0-9])') && flag ) 
{
  report =
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : migrate to 9.x (9.0(1.2) / 9.1(1.2) or later)\n';
  security_hole(port:0, extra:report);
  exit(0);
}

# compare the ASA version versus all fixed releases.  The comparison is only made if the major versions match up
fixed_releases = make_list(
  '7.2(5.10)',
  '8.0(5.31)',
  '8.2(5.38)',
  '8.3(2.37)',
  '8.4(5.3)',
  '8.6(1.10)',
  '8.7(1.4)',
  '9.0(1.2)',
  '9.1(1.2)'
);
foreach fix (fixed_releases)
{
  if (check_asa_release(version:ver, patched:fix))
  {
    report =
      '\n  Installed release : ' + ver +
      '\n  Fixed release     : ' + fix + '\n';
    security_hole(port:0, extra:report);
    exit(0);
  }
}

audit(AUDIT_INST_VER_NOT_VULN, 'ASA', ver);

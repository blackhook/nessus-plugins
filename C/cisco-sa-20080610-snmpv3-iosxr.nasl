#TRUSTED 4343d520082fa88e223fb74cb1254bffd6f58c9c484a821cd7c1068fdd7c32e9023bfa876dd57f0f61647198f85d3814699289f3e6468e27c8ac81ba0325bccfe02af5fd21246d7650e4b65aad1bf1c92085ed8bbd2009188e1d4cde0115cb14a79742b71f160d66a5876abcd773af105ad842b4f21691944ae974b382d03b32ed0af4bcc1a5a42e2106cdc6bf065006e46b9be918796f57466a474c4b217885c108dfc73339e39b5db7c8b73ba902365e46d1a5a0c46dea824089490a9866d2b89bbc900ddf6179e7fb03d253ba52380a7cfd523ea7b9d6848c791f87edb112766b575341d6245c64453cee194a0b21ce975baddfed60954c4bfdc4a5c08ebac9a695d14a9929f87cdb40dc26ae2b993265be005a731fb53ac1725db0325824cce6371d5ce8652a335d3db5f3e20a082dd5584670c458b6d61f1acc795f90e482c691797fb62e753f584f519c0f810ce622efea526cf894a79e8b2a6ecc1bb6a28431673b4f55f7f1e97df609795536a3c26f198e28b5ee9347056d72bf80e72292c0e68ae4193e57f7439a1fc6f9b11512e687026290a5e5772456890d2b8ef30dd2d737862bad82e051d13c35d0a1d2370d3410a120964d14ac501c0af0c2b0d521f73362fbabfaada2549f16f88e2e26396028809d8512d766782271961e09bf63e5be805f821742dfa560866738d0f264945d9d302f5a62bd17723de8ee
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20080610-snmpv3.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(71433);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2008-0960");
  script_bugtraq_id(29623);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsf30109");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20080610-snmpv3");
  script_xref(name:"CERT", value:"878044");
  script_xref(name:"EDB-ID", value:"5790");

  script_name(english:"SNMP Version 3 Authentication Vulnerabilities (cisco-sa-20080610-snmpv3)");
  script_summary(english:"Checks the IOS XR version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple Cisco products contain either of two authentication
vulnerabilities in the Simple Network Management Protocol version 3
(SNMPv3) feature.  These vulnerabilities can be exploited when
processing a malformed SNMPv3 message.  The vulnerabilities could allow
the disclosure of network information or may enable an attacker to
perform configuration changes to vulnerable devices.  The SNMP server is
an optional service that is disabled by default in Cisco products.  Only
SNMPv3 is impacted by these vulnerabilities.  Workarounds are available
for mitigating the impact of the vulnerabilities described in this
document.  Note: SNMP versions 1, 2 and 2c are not impacted by these
vulnerabilities.  The United States Computer Emergency Response Team
(US-CERT) has assigned Vulnerability Note VU#878044."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20080610-snmpv3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0784818d");
  script_set_attribute(
    attribute:"solution", 
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20080610-snmpv3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-0960");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
report = "";
override = 0;

cbi = "CSCsf30109";

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
if ((cisco_gen_ver_compare(a:version, b:"3.3.1") >= 0) && (cisco_gen_ver_compare(a:version, b:"3.3.2") == -1)) flag ++;
fixed_ver = "3.3.2.6";

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_snmp_group", "show snmp group");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"[Ss]ecurity\s+[Mm]odel:usm", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report =
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed Release : ' + version +
    '\n    Fixed Release     : ' + fixed_ver + '\n';

  security_hole(port:port, extra:report + cisco_caveat(override));
  exit(0);

}
else audit(AUDIT_HOST_NOT, "affected");

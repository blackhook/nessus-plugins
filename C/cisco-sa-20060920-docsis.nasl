#TRUSTED ac95b3eedf8e610ae47c856e6d5678614b0787132f9e40fe3a41e62aceb59f28021b28e057d97c8bc5e01943177db543ee18643d1e3cc2fb77c7b7700d500f95d4185d012a85643c4612a81e4defa2538eb65624aa9539e1d9efa8c5d07e5c98744f4d29955df2392c5a507507658cc23e33a8a26221d8df1275d289388d4b5b0db91c462531e39b00dbc27bacee8ff4dff214cc2ecdc9e7ed094eae58ced04b80117096cf9c2e9644d948af6abbd2d1b9cc78b23b90e4967ba3c551379221d2d91f585247aa894e33bfb763744d8c7bbd3bbb9957599c031b0b2b8e45bf898c1c7d7395a61bdcddf20bfbe0e36012651fa0a61a52cb05287ea7ddc7e4c3b4b9dd7c9e923cd721ea9447d388b8b105e751e7005b77c0d7c3bcd6ddcb2fca951a47608f9a9034c032f0aeca2395f2956dbc8a35feb9264ea737fb966cda2f8260b741e41e2d2727b06a86e7c3f83433592316e877676be265850793fc0421cfcdbfd9222ba312da8bef362da79034db58de66d91565661f59ec2a938fbbf10de39a3587041fbd9a52e48926d21f0a945ed9126d8546c8b09da204fc61fe74d2039228867445b3e836fd83e03ecc2b5c1045f8f1c709428a720a50d44f9a9e361aa6494c6bf4ee92ed2de00b2847096b0d4a834b2232acfa6829655115f1186a2f8fd4baab736c729d7637c136eb936945963e11414f03edaa24fd91ef6ade2879
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17782);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2006-4950");
  script_bugtraq_id(20125);
  script_xref(name:"CERT", value:"123140");
  script_xref(name:"CISCO-BUG-ID", value:"CSCsb04965");
  script_xref(name:"CISCO-BUG-ID", value:"CSCsb06658");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20060920-docsis");

  script_name(english:"DOCSIS Read-Write Community String Enabled in Non-DOCSIS Platforms");
  script_summary(english:"Checks IOS version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description",
    value:
"Vulnerable versions of Cisco IOS contain a default hard-coded
community string when SNMP is enabled on the device.  An additional
read-write community string may be enabled if the device is configured
for SNMP management, which would allow privilege access to the
device."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20060920-docsis
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72107c9e");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20060920-docsis."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencie("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

if (version == '12.4(2)T4') flag++;
else if (version == '12.4(2)T3') flag++;
else if (version == '12.4(2)T2') flag++;
else if (version == '12.4(2)T1') flag++;
else if (version == '12.4(2)T') flag++;
else if (version == '12.4(2)MR1') flag++;
else if (version == '12.4(2)MR') flag++;
else if (version == '12.4(1a)') flag++;
else if (version == '12.4(1)') flag++;
else if (version == '12.3(14)YX1') flag++;
else if (version == '12.3(14)YU1') flag++;
else if (version == '12.3(14)YU') flag++;
else if (version == '12.3(14)YT1') flag++;
else if (version == '12.3(14)YT') flag++;
else if (version == '12.3(11)YS1') flag++;
else if (version == '12.3(11)YS') flag++;
else if (version == '12.3(14)YQ7') flag++;
else if (version == '12.3(14)YQ6') flag++;
else if (version == '12.3(14)YQ5') flag++;
else if (version == '12.3(14)YQ4') flag++;
else if (version == '12.3(14)YQ3') flag++;
else if (version == '12.3(14)YQ2') flag++;
else if (version == '12.3(14)YQ1') flag++;
else if (version == '12.3(14)YQ') flag++;
else if (version == '12.3(14)YM7') flag++;
else if (version == '12.3(14)YM6') flag++;
else if (version == '12.3(14)YM5') flag++;
else if (version == '12.3(14)YM4') flag++;
else if (version == '12.3(14)YM3') flag++;
else if (version == '12.3(14)YM2') flag++;
else if (version == '12.3(11)YK2') flag++;
else if (version == '12.3(11)YK1') flag++;
else if (version == '12.3(11)YK') flag++;
else if (version == '12.3(11)YJ') flag++;
else if (version == '12.3(8)YI3') flag++;
else if (version == '12.3(8)YI2') flag++;
else if (version == '12.3(8)YI1') flag++;
else if (version == '12.3(8)YH') flag++;
else if (version == '12.3(8)YG4') flag++;
else if (version == '12.3(8)YG3') flag++;
else if (version == '12.3(8)YG2') flag++;
else if (version == '12.3(8)YG1') flag++;
else if (version == '12.3(8)YG') flag++;
else if (version == '12.3(11)YF4') flag++;
else if (version == '12.3(11)YF3') flag++;
else if (version == '12.3(11)YF2') flag++;
else if (version == '12.3(11)YF1') flag++;
else if (version == '12.3(11)YF') flag++;
else if (version == '12.3(8)YD1') flag++;
else if (version == '12.3(8)YD') flag++;
else if (version == '12.3(8)YA1') flag++;
else if (version == '12.3(8)YA') flag++;
else if (version == '12.3(8)XY7') flag++;
else if (version == '12.3(8)XY6') flag++;
else if (version == '12.3(8)XY5') flag++;
else if (version == '12.3(8)XY4') flag++;
else if (version == '12.3(8)XY3') flag++;
else if (version == '12.3(8)XY2') flag++;
else if (version == '12.3(8)XY1') flag++;
else if (version == '12.3(8)XY') flag++;
else if (version == '12.3(11)XL1') flag++;
else if (version == '12.3(11)XL') flag++;
else if (version == '12.3(4)XD3') flag++;
else if (version == '12.3(4)XD2') flag++;
else if (version == '12.3(4)XD1') flag++;
else if (version == '12.3(4)XD') flag++;
else if (version == '12.3(14)T7') flag++;
else if (version == '12.3(14)T6') flag++;
else if (version == '12.3(14)T5') flag++;
else if (version == '12.3(14)T3') flag++;
else if (version == '12.3(14)T2') flag++;
else if (version == '12.3(14)T1') flag++;
else if (version == '12.3(14)T') flag++;
else if (version == '12.3(11)T6') flag++;
else if (version == '12.3(11)T5') flag++;
else if (version == '12.3(11)T4') flag++;
else if (version == '12.3(11)T3') flag++;
else if (version == '12.3(11)T2') flag++;
else if (version == '12.3(11)T') flag++;
else if (version == '12.3(8)T9') flag++;
else if (version == '12.3(8)T8') flag++;
else if (version == '12.3(8)T7') flag++;
else if (version == '12.3(8)T6') flag++;
else if (version == '12.3(8)T5') flag++;
else if (version == '12.3(8)T4') flag++;
else if (version == '12.3(8)T3') flag++;
else if (version == '12.3(8)T1') flag++;
else if (version == '12.3(8)T') flag++;
else if (version == '12.3(7)T9') flag++;
else if (version == '12.3(7)T8') flag++;
else if (version == '12.3(7)T7') flag++;
else if (version == '12.3(7)T6') flag++;
else if (version == '12.3(7)T4') flag++;
else if (version == '12.3(7)T3') flag++;
else if (version == '12.3(7)T2') flag++;
else if (version == '12.3(7)T10') flag++;
else if (version == '12.3(7)T1') flag++;
else if (version == '12.3(7)T') flag++;
else if (version == '12.3(4)T9') flag++;
else if (version == '12.3(4)T8') flag++;
else if (version == '12.3(4)T7') flag++;
else if (version == '12.3(4)T6') flag++;
else if (version == '12.3(4)T4') flag++;
else if (version == '12.3(4)T3') flag++;
else if (version == '12.3(4)T2') flag++;
else if (version == '12.3(4)T11') flag++;
else if (version == '12.3(4)T10') flag++;
else if (version == '12.3(4)T1') flag++;
else if (version == '12.3(4)T') flag++;
else if (version == '12.2(15)ZJ3') flag++;
else if (version == '12.2(15)ZJ2') flag++;
else if (version == '12.2(15)ZJ1') flag++;
else if (version == '12.2(15)ZJ') flag++;
else if (version == '12.2(15)MC2b') flag++;
else if (version == '12.2(15)MC2a') flag++;
else if (version == '12.2(15)MC2') flag++;
else if (version == '12.2(15)MC1c') flag++;
else if (version == '12.2(15)MC1b') flag++;
else if (version == '12.2(15)MC1a') flag++;
else if (version == '12.2(15)MC1') flag++;
else if (version == '12.2(8)MC2d') flag++;
else if (version == '12.2(8)MC2c') flag++;
else if (version == '12.2(8)MC2b') flag++;
else if (version == '12.2(8)MC2a') flag++;
else if (version == '12.2(8)MC2') flag++;
else if (version == '12.2(8)MC1') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_snmp_community", "show snmp community");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Community name:", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

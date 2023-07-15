#TRUSTED 510c7fbe9816d2d0c4bd28014c99f98c2c3c652755bdecb3c8e54563635712efb3d2cdb840055785e61f805eb0d2a62f3726ab54ca81843fd44a7249dbab64ae165a06a8fe178a01256963d281cf715987005dba742f8c5127fc8d1c617765362d1681e306ef9ca3e9be42952c5eba6c5bc25eede700ce0c336acbc2f761419f778221dd6c96635e7a364ba379cf36de3e57a2e06c56252b888e3131d7c2f050dc1521aae167c755efef18e71796b19c703d42731d65c20ec6afa77442576511ddac67a8cf6ead79cf1f450d7ada2c8296e1a6d113c5409382850e5e394a7e713e3caf5223887d0c6371c0e103c3c4059d91d1de2d757678daa69e6cf4a64d7f25b3a01a0c8a4ab7a7241f779cd3d135ba7283b688a7e97b3872a8a2f53256e0cad19055959e2a52363b6d2ad74a1cba8d24950ed9f17863e11939481194d5a53c55a270a5676770eb508e44c35e9ba5d7500dc6a662e0a116e565b1113ff80fa8a16ad8aa7fba421df14198cf6801eec0286794e8949c4b6a00697473ba9ed942e06901d51dd2d0df160e4f191ed02aec67acfbd5ccdfe10aee02395a918f9b05f20146876d05b79ae55e8f82728ca61c58747240650e83fa55068ff2403324ec06771b9aa10deff522c2e0c6f3b88cb095206b9332dbeacfefb62827dc6638e7b8da2a2cdb446c205372ea7c41aebe5279403e3641547cc078a07d299074c7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81594);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/25");

  script_cve_id("CVE-2015-0235");
  script_bugtraq_id(72325);
  script_xref(name:"CERT", value:"967332");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus69732");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150128-ghost");

  script_name(english:"Cisco IOS XE GNU C Library (glibc) Buffer Overflow (CSCus69732) (GHOST)");
  script_summary(english:"Checks IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of Cisco IOS XE software
that is affected by a heap-based buffer overflow vulnerability in the
GNU C Library (glibc) due to improperly validated user-supplied input
to the __nss_hostname_digits_dots(), gethostbyname(), and
gethostbyname2() functions. This allows a remote attacker to cause a
buffer overflow, resulting in a denial of service condition or the
execution of arbitrary code.

Note that only the following devices are listed as affected :

  - Cisco ASR 1000 Series Aggregation Services Routers
  - Cisco ASR 920 Series Aggregation Services Routers
  - Cisco ASR 900 Series Aggregation Services Routers
  - Cisco 4400 Series Integrated Services Routers
  - Cisco 4300 Series Integrated Services Routers
  - Cisco Cloud Services Router 1000V Series");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCus69732");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150128-ghost
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd2144f8");
  # https://www.qualys.com/research/security-advisories/GHOST-CVE-2015-0235.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7a6ddbd");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCus69732.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0235");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim GHOST (glibc gethostbyname) Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
model   = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");

# Model check
# Per Bug CSCus69732
if (
  !(
    "ASR1k"    >< model ||
    "ASR920"   >< model ||
    "ASR900"   >< model ||
    "ISR4400"  >< model ||
    "ISR4300"  >< model ||
    "CSR1000V" >< model
  )
) audit(AUDIT_HOST_NOT, "an affected model");

# Version check
# Per Bug CSCus69732
# - top list (raw)
# - and bottom list (converted)
if (
  version == "3.10.0S" || #bl
  version == "3.10.4S" || #bl
  version == "3.11.0S" || #bl
  version == "3.11.2S" || #bl
  version == "3.11.3S" ||
  version == "3.12.0S" || #bl
  version == "3.12.1S" || #bl
  version == "3.13.0S" || #bl
  version == "3.13.2S" ||
  version == "3.14.S"  ||
  version == "3.4.7S"  ||
  version == "3.7.0S"  || #bl
  version == "3.7.6S"
)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCus69732' +
    '\n  Installed release : ' + version +
    '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

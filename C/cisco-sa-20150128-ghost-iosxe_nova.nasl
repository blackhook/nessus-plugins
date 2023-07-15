#TRUSTED 70ddb6fe0d8dbc7ccaf382570f0f476d58fc99b615c444c83fb7bf51899e7714303756300409a77fbd8bd0ff36774383ecd3751628bc4ed03d7337a4e6d0034adbd1ae03e28a8eb5f737c813b05702889b5d7a64fffee4ad39c71e0a47c9354c2150ef6f089df7712e51f3b724a4bdd66332bdd7234e479a0dc98cffc3f74137a6b80be4cd00f5a4a3c0667691bd0185881b902d85912243bc9c4e7d48aeb6cf8b4fd79e7d087d2b16a1e1192b0ff922689021fb0431b1b33aefb452cd5555f424328105481ff422b0183ac870cbd8a5050ea3ce13749849d5d7d3adcd3be86e705182abf147b35679ee304a817dd50de295f4c5a375fbf7a47df6dffeb42debea8f7e74ac82e35b9fd000fa8d3a09f097afad89d1d457e665aa50bfc88be38faf61e78802427d610616dea79ab04b76a97a1e2759af0a0584ce16df3b073e87b3996645c1478ef9851ec17b739e2583d04afc4529eaf7dc48e095aa790b9c2833146f7ef1d4e95ba795944dce1ac9cb2b992063288dcc41c16889c66b8a5cf3ac9cc5572a3b9c66631f95bfc1eadb5dd5bfa92914cdc3fd0f2cb181bad342f7e83e758da4884dd5091309c77a56bd79f2d87d5936b5c703b241219394b4003b4873f8657c366f30ca5eda4b3faa75dbdea0d3be7667f0bd8139dd221fff4b8e7d90efbe30a433799c0c1fdcc687deab476fd1040626779547e72a98f337edff
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81595);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-0235");
  script_bugtraq_id(72325);
  script_xref(name:"CERT", value:"967332");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus69731");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150128-ghost");

  script_name(english:"Cisco IOS XE GNU GNU C Library (glibc) Buffer Overflow (CSCus69731) (GHOST)");
  script_summary(english:"Checks IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of Cisco IOS XE software
that is potentially affected by a heap-based buffer overflow
vulnerability in the GNU C Library (glibc) due to improperly
validated user-supplied input to the __nss_hostname_digits_dots(),
gethostbyname(), and gethostbyname2() functions. This allows a remote
attacker to cause a buffer overflow, resulting in a denial of service
condition or the execution of arbitrary code.

Note that this issue only affects those IOS XE instances that are
running as a 'Nova' device, and thus, if the remote IOS XE instance
is not running as a 'Nova' device, consider this a false positive.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCus69731");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150128-ghost
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd2144f8");
  # https://www.qualys.com/research/security-advisories/GHOST-CVE-2015-0235.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7a6ddbd");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCus69731.");
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

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

# Bug notes these are affected on 'Nova' devices
# only.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# Per Bug CSCus69731 (converted from IOS vers)
# No model restrictions listed
# Further note that IOS version '15.0(2)EX'
# is not mapped and thus, omitted.
if (
  version == "3.1.0SG" ||
  version == "3.2.0SE" ||
  version == "3.2.0SG" ||
  version == "3.2.0XO" ||
  version == "3.3.0SE" ||
  version == "3.3.0XO" ||
  version == "3.4.0SG" ||
  version == "3.5.0E"  ||
  version == "3.6.0E"  ||
  version == "3.7.0E"
)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCus69731' +
    '\n  Installed release : ' + version +
    '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

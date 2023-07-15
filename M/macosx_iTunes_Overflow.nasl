#TRUSTED 3d1169e0053d4697c47b0324b4cdec68bdee710c5ad93aeaeb8bd864350483d4447045287001608d8973b219185fd84f73811f5bb7d47f8a1179a557c36b7de99e39645481bffad1c402f32662eee22006859448368324855c57b341da15a1403222f4a1683ad20c2ab21d60bc0f32a07be40871b66d80e7851b1e763b76a364722a5551091ba1d6b8617cc7c633cf30a6880fd81895e623f80344ae8bd883a7ab31b28e88295001cf5eb47d0d42052d8078c17eadcf40c6753ef2f70d440512ebad78cf8207893431057a815c0fffe4374ff28716afae87137bc7ef453a0eec10ef3ec4fc60c2672dd9918ab0b328ebb88af91dca91088542b8c42ee8f5e3b1d5a2ff35c0900ca29228713515770e0aebe5ea076eae123f08f418dc83b78fc4655c5d3031c3d5bd03e9d6dc2db5906be4907317f14db29d1dd084c232295b9b187ab02087ba36c0cc2cf11db732f855c3729199f7dce55ad8c376d6ed0511e532cc4661835332e172822808b4fcfdb799520795b24d343fe49679c37de3977ae68954fd91055e55b12f09bcb7c2e37e1a12f598768083531b501619522c02696d3c157317c37422e5986fc1298463fd89efc61c886153b1c6606211fad02d6541bbd48b52cd6ac106e662097aee2c22454f7e87456cd66bc6af969ae21375c46c35bab29664666b487b5c2e857c114f2f62eccd1c5c9961a5e5c9efa824bbea
#TRUST-RSA-SHA256 2cfc4242fd1ce04ca86da3850a39781630403c9d9a7a7f450c84ea1eae4d363f2bc1ee046e379e18dea331e067c489c32caae2c25689f682c9e0a478c9e191251a25ec8f818daf90b07e13ed5ef1474a0724c11ec62f8e119a872509e2b24287bcfaf7f8817c14519566dea9f76bada5180ef4214537c36a75dbb95c156914904723526d4dbf1a430e3fe7e6449463357393ae4f1a507cda32e35c400000955724b88e4797f9ad938f9e2a8c087fbd1e9bc1df380be5fa11f43f32ba300d7421a0cacdad8b9e0337abb0e536ab28283c7a1c993132f67e509952e74066c6f2eb5b62d309099fd659889ea5b0e949e09ca9c56c2beb4f589aa965bbde729d1baa5f8b833b0b7f7fa889accde79025ea1784cc46e374a15c7f1d1c2090974eea32c8df14d1029fd2b1f7ec26e901152ecc8604620985aec3d874337c8e972c7ea0b179012b1bf08b1e6ebed905f7e56932c4cf21bc2cc7a0a4ff8ace1a251a232a4b0bbb42be82d0afbd748450d574bb374e34a175d9529f84796bec0c7eea42b7c5bfc731c5ef3891dcc02275c59f05d09cc5c0152668364dbdd6335708f65dc34cc164823653895c9e227686b0406c423952dd57d8229da864c3b7402a0898646b0cdbfb4fb83475d03f3810df1fc60607e731c7402c6d24a2c80a8404caf3a775c21992e6c42854c7cf37577f99e5ed6ceaa7b6df0ac8ad85d508c5ba499497
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16151);
 script_version("1.26");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/01");

 script_cve_id("CVE-2005-0043");
 script_bugtraq_id(12238);
 script_xref(name:"Secunia", value:"13804");
 script_xref(name:"APPLE-SA", value:"APPLE-SA-2005-01-11");

 script_name(english:"iTunes < 4.7.1");
 script_summary(english:"Check the version of iTunes");

 script_set_attribute( attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a security
issue." );
 script_set_attribute( attribute:"description",  value:
"The remote host is running a version of iTunes which is older than
version 4.7.1.  The remote version of this software is vulnerable
to a buffer overflow when it parses a malformed playlist file
(.m3u or .pls files).  A remote attacker could exploit this by
tricking a user into opening a maliciously crafted file, resulting
in arbitrary code execution." );
 # https://lists.apple.com/archives/security-announce/2005/Jan/msg00000.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eba3be11");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Jan/119");
 script_set_attribute(attribute:"solution", value:"Upgrade to iTunes 4.7.1 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-0043");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Apple ITunes 4.7 Playlist Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/01/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"MacOS X Local Security Checks");

 script_copyright(english:"This script is Copyright (C) 2004-2023 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}

include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

cmd = GetBundleVersionCmd(file:"iTunes.app", path:"/Applications");

if ( islocalhost() )
 buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
else
{
 ret = ssh_open_connection();
 if ( ! ret ) exit(0);
 buf = ssh_cmd(cmd:cmd);
 ssh_close_connection();
}

if ( ! buf ) exit(0);
if ( ! ereg(pattern:"^iTunes [0-9.]", string:buf) ) exit(0);
version = ereg_replace(pattern:"^iTunes ([0-9.]+),.*", string:buf, replace:"\1");
set_kb_item(name:"iTunes/Version", value:version);
if ( egrep(pattern:"iTunes 4\.([0-6]\..*|7|7\.0)$", string:buf) ) security_warning(0);

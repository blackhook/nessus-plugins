#TRUSTED 80bdef2c40ae44dc2620884db26dd8182d8d4cf1fcced59e6667140764683c8ffc82b1d4fdeccd12c6eed0061810a92f71ab48f6d00faa0012a75d792cb22f20e165b4dbc6dc6b63c5fb8ae26663ebce58a540a5b0fec391b141ee0e7d35299f7e50c0d0153a4a40840a160a2fdd301d1c15680d8c1baf9206ce1679fe549008ccd0efa2e7929e074af485b7af5a8087e4eca47b3005462d61a89fe6b095d205fcaa41c1c36e79db34e6d3fb024e913f4b4838d1347b05bf7f954f9be330d1bc4b7213b2a62d19a24ce8eb888dd1a532ab164958a10afda02331951123d16106f1ec2f779fcb3a500198975fcb725122849fe88a99c214459569c317b9a8e5506e4874d26376f89dcb6786b317dc3d05dfab92ca41ca30dd5417067fbe29be1ff74a731f20f36ebc784bfa0cb7f0dac4d320684556f5916d24a7485838d92bc0f1194544afc6dbe674762d06817594e7fc9cdf53350707ee5119695ce1d95a5c545e328fb8f73d0d9c4995c6a8d089fb5d8cb5b80751a62f12d59fd3eb78501df7d7bb481eb6b677d6f8532413b47fce04a05f4b226da21cb2722e649c2dda66e1e4e91f4ef55775496147c3763176dbc38660001d104b664d28258746a131f5d9792bd81c055b42191fdcd60fb839a201895382cf945ca034e432f0c78b4a1b0f4300e35cf30a4b10c60f948687230cb177b58240dc8dbbd404c6af29e9c289
#TRUST-RSA-SHA256 b0bdf27c4bab75524d7bd7bb37cca7d96ebc3bf861dc550d00a2aa06361ded750121153018176559c6b49c6f16eb7638ad2528fc7df2c6000566d75f8abfb47c366773c3132a4341ecffeffced7865dbe95e2dc3fffdb6acc718d167a805e7341c1b0f7e79ca20838fceb8581b631323e8b96c263cf931285ad905e5362446525c72f875655e5d30d575e607fb444f6d156b16ee56df1d22aa44816270c6cef5275ed825c0a30896cab91ad966ee192096bfc8281607cb2fd2f061b7d0208c29a455837aedf70af783d09a363978feba2f8b8ddae8ac65d2fbbfaf683e9c5cd77cd8624f64d1dc0744d680949c4b2542fefd045c08e59a62d1492117736872c14a49ab1bc6c16b3fabc1aa295e641f7f7a1ec3eb08845c35cd64900fa2f08e4c1a6d23a8c487af9cd79bb2d41af7457fa238a534af796d1e34ed2d961f28deb3b9bc55acdaf4f7d7a51d3ca7b54b3a96d16cb2c94ea05453a2f8fac5cfd236f110d5e136c7e6a680cae4932b6b621706e0324bbd7a3e0939ec3928d4fddb3613033edbec7e0ef2126f718a95ad37d83877ae02f7b1cec52410464752a333f023d92e45cde0cd96cbfc48a6f0c72304b68114bf1e4406465b8d8bd35e5096eedc619588a58983046b667fc0951f878a538221f5c134a5f19c4461e5b85894a6291f56e546518edba54914d3cd8c19a3bfc959698ba7bc18309f6ac569e488bd6f
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173971);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/13");

  script_cve_id("CVE-2023-20123");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe66449");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe66538");
  script_xref(name:"CISCO-SA", value:"cisco-sa-duo-replay-knuNKd");

  script_name(english:"Cisco Duo Authentication for macOS Logon Offline Credentials Replay (cisco-sa-duo-replay-knuNKd)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Duo Authentication for macOS is affected by a vulnerability. A
vulnerability in the offline access mode of Cisco Duo Two-Factor Authentication for macOS and Duo Authentication for
Windows Logon and RDP could allow an unauthenticated, physical attacker to replay valid user session credentials and
gain unauthorized access to an affected macOS or Windows device. This vulnerability exists because session credentials
do not properly expire. An attacker could exploit this vulnerability by replaying previously used multifactor
authentication (MFA) codes to bypass MFA protection. A successful exploit could allow the attacker to gain unauthorized
access to the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-duo-replay-knuNKd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a6a74a2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe66449");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe66538");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwe66449, CSCwe66538");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20123");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:duo");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macos_cisco_duo_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Cisco Duo");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version')) audit(AUDIT_OS_NOT, 'macOS / Mac OS X');

var app = 'Cisco Duo';
var app_info = vcf::get_app_info(app:app);

var fixed_version = '2.0.1';

# Cannot for offline access features
if (report_paranoia < 2 && ver_compare(ver:app_info.version, fix:fixed_version, strict:FALSE) < 0)
  audit(AUDIT_POTENTIAL_VULN, app, app_info.version);

var constraints = [
  { 'fixed_version' : fixed_version }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

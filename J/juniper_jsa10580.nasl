#TRUSTED 60e880fb2e4b2cf56fae277e075abf16532d930b10c45cc3346ec20e892c2153081d67624a52330365ea4c13d925da493980cb24847c71296ba01ee8954a87a515fb2dc55f5e6326d15b122eefaadd150e261d212c23c0b49dbacfc881045f1bfef6b7a0d2bffac723c8b252b352b10543e050830c832a1b97cd859aef833225f468a93cfa47d5afe8986fd26227a728cd4ac8a8de5ca352275a241d95d410c05014e6e2a1dbd0e4f01cbd7209c3b25bcf0547b503790e507107d23800198e705293e619953104b6ee29d9ef0f4a1daaf532e878d2748394fc88164bae270e699d99914708a331e6d7d419ca742180f754256cb2be2e1c564009e5fb613b047836c000e064d65be4b41fa7beb365099e132ce00cf4ac6ddc8dee28a3f289650953ab2b83aee64f91d4bb25f9e3ef8bdcd316eba401f8571125bfd0d63c4d66f025870ffef591c32267b65080e0bcc9b9f35ebee59ecad39bde32767a21b317fce89f4e1f6af4647fae3d1d7dc4e6335a8c7559ce8ab23895e9c4646927d8cca837f22ea5b5ecd395c6a434f459e5facde3674602dd7aa10ef6cb0c4fbc23322b54350b29560291ba1d2118ab3871c9b4fdda9caa0b2a9496eb5f81181ebf3f9252fbbce4c9659ac20f0a72f0f078e20297bbd31c39dd89ac8f488611d1d132a74dbc6c6e99fc038dd433028f91aeb5956f9974605f935dec1b2545d777b23785
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68913);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2011-1473");
  script_bugtraq_id(48626);
  script_xref(name:"JSA", value:"JSA10580");

  script_name(english:"Juniper Junos SSL/TLS Renegotiation DoS (JSA10580)");
  script_summary(english:"Checks the Junos version, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability. The
SSL/TLS implementation on the remote host allows clients to
renegotiate connections. The computational requirements for
renegotiating a connection are asymmetrical between the client and the
server, with the server performing several times more work. Since the
remote host does not appear to limit the number of renegotiations for
a single TLS / SSL connection, this permits a client to open several
simultaneous connections and repeatedly renegotiate them, possibly
leading to a denial of service condition.

Note that this issue only affects devices with J-Web or the SSL
service for JUNOScript enabled.");
  script_set_attribute(attribute:"see_also", value:"http://www.ietf.org/mail-archive/web/tls/current/msg07553.html");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10580");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10580.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

if (compare_build_dates(build_date, '2013-06-13') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['10.4'] = '10.4S14';
fixes['11.4'] = '11.4R7';
fixes['12.1'] = '12.1R6';
fixes['12.1X44'] = '12.1X44-D20';
fixes['12.2'] = '12.2R3';
fixes['12.3'] = '12.3R2';
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# HTTPS or XNM-SSL must be enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  patterns = make_list(
    "^set system services web-management https interface", # HTTPS
    "^set system services xnm-ssl" # SSL Service for JUNOScript (XNM-SSL)
  );
  foreach pattern (patterns)
  {
    if (junos_check_config(buf:buf, pattern:pattern)) override = FALSE;
  }
  if (override) audit(AUDIT_HOST_NOT,
    'affected because neither J-Web nor the SSL service for JUNOScript are enabled');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);

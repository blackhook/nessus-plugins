#TRUSTED 8d560c27fcb62bf532f6aa70c67e990b11c5f44076cdb05a2493e6fdbe176daba2bb8af9fc8d95d28287c91a4637942f55ad5e5970a0e4b00e5a6fa02d19e32218a3aaa786a9a49d53c64e219d7eb99be3f574a754d78ba458c50a66551ac7e0a59db70c0054c5715177ae33abb37df9aa25f988c8ea472bc7249ec3ad6fc5dda87e2ac0539672bb6ca3aeeb43c64b9409540bc9740c87c359ead516f897b597afefea59b332618b0cd1b852cba5708e7d45193c8785ef10b981c9b185a0920c1ae0a41edcdd7d8bfb76f341d04feae764cbc5778a7420623e7b4f60e4fcce98580b329b850f6d2d746edcc8c6e4a61949c737af1492f560cc71bbfeaec7d8465f25f4d2b79219afa1a97459c6cf80a4eb702667c7fc336c85503b4e2e495487462dd43da0c79fd38503f2d1945fc39737a03f8c5d2a1ca33105de9445fea3173a5516eea93a547bf50bd5306a398d3c2304d2cc046cea1cb0b827fc817e458dc6e246ff99cb3e2e84f8639074812608fadbb33165ddf85748ca3d65d1dd138e48875812c11ded7dcba02652722eb01314c7b2649a547cdd6f9aa42e4d4521163c5948504ea1bfbca4a570b961c1ba95cb6c2a4d70cfab13ff42e39f574265ae9529df5b5ee032cfad7c492676799a46dea4d2ea5310dbd48735df6dd7f42cfa1fb2bbcf6fb727f86ad925c599d6c91c8769a39da3e26fd3774248c770802e97
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78420);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id(
    "CVE-2014-3509",
    "CVE-2014-3511",
    "CVE-2014-3512",
    "CVE-2014-5139"
  );
  script_bugtraq_id(69077, 69079, 69083, 69084);
  script_xref(name:"JSA", value:"JSA10649");

  script_name(english:"Juniper Junos Multiple OpenSSL Vulnerabilities (JSA10649)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by multiple vulnerabilities in the implementation of
OpenSSL :

  - An error exists related to 'ec point format extension'
    handling and multithreaded clients that allows freed
    memory to be overwritten during a resumed session.
    (CVE-2014-3509)

  - An error exists related to handling fragmented
    'ClientHello' messages that allows a man-in-the-middle
    attacker to force usage of TLS 1.0 regardless of higher
    protocol levels being supported by both the server and
    the client. (CVE-2014-3511)

  - A buffer overflow error exists related to handling
    Secure Remote Password protocol (SRP) parameters having
    unspecified impact. (CVE-2014-3512)

  - A NULL pointer dereference error exists related to
    handling Secure Remote Password protocol (SRP) that
    allows a malicious server to crash a client, resulting
    in a denial of service. (CVE-2014-5139)

Note that these issues only affects devices with J-Web or the SSL
service for JUNOScript enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10649");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140806.txt");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10649.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();
fixes['13.3'] = '13.3R3-S2';
fixes['14.1'] = '14.1R2-S2';
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (ver =~ "^13\.3[^0-9]")
  fix = "13.3R3-S2 or 13.3R4";
else if (ver =~ "^14\.1[^0-9]")
  fix = "14.1R2-S2 or 14.2R1";

# Check for J-Web or SSL service for JUNOScript (XNM-SSL)
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  patterns = make_list(
    "^set system services web-management https interface", # J-Web HTTPS
    "^set system services xnm-ssl" # SSL Service for JUNOScript (XNM-SSL)
  );
  
  foreach pattern (patterns)
  {
    if (junos_check_config(buf:buf, pattern:pattern))
      override = FALSE;
  }
  if (override) exit(0, "Device is not affected based on its configuration.");
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100419);
  script_version("1.11");
  script_cvs_date("Date: 2019/01/02 11:18:37");

  script_cve_id(
    "CVE-2016-4971",
    "CVE-2016-5696",
    "CVE-2017-3731",
    "CVE-2017-7409",
    "CVE-2017-7644",
    "CVE-2017-7945"
  );
  script_bugtraq_id(
    91530,
    91704,
    95813,
    98404,
    97953,
    98396
  );
  script_xref(name:"EDB-ID", value:"40064");

  script_name(english:"Palo Alto Networks PAN-OS 6.1.x < 6.1.17 / 7.0.x < 7.0.15 / 7.1.x < 7.1.10 / 8.0.x < 8.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Palo Alto Networks PAN-OS running on the remote host is
6.1.x prior to 6.1.17, 7.0.x prior to 7.0.15, 7.1.x prior to 7.1.10,
or 8.0.x prior to 8.0.2. It is, therefore, affected by multiple
vulnerabilities :

  - A flaw exists in the GNU wget component when handling
    server redirects to FTP resources due to the destination
    file name being obtained from the redirected URL and not
    the original URL. An unauthenticated, remote attacker
    can exploit this, via a specially crafted response, to
    cause a different file name to be used than intended,
    resulting in writing to arbitrary files. (CVE-2016-4971)

  - A flaw exists in the Linux kernel due to improper
    determination of the rate of challenge ACK segments. An
    unauthenticated, remote attacker can exploit this to
    gain access to the shared counter, which makes it easier
    to hijack TCP sessions using a blind in-window attack.
    This issue only affects version 7.1.x. (CVE-2016-5696)

  - An out-of-bounds read error exists when handling packets
    using the CHACHA20/POLY1305 or RC4-MD5 ciphers. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted truncated packets, to cause a denial
    of service condition. This issue does not affect version
    6.1.x. (CVE-2017-3731)

  - A cross-site scripting (XSS) vulnerability exists in
    GlobalProtect due to improper validation of
    user-supplied input to unspecified request parameters
    before returning it to users. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. This issue only affects version 7.0.x.
    (CVE-2017-7409)

  - A flaw exists in the web-based management interface due
    to improper permission checks that allows an
    authenticated, remote attacker to disclose sensitive
    information. This issue only affects versions 6.1.x,
    7.0.x, and 8.0.x. (CVE-2017-7644)

  - An information disclosure vulnerability exists in the
    GlobalProtect external interface due to returning
    different error messages when handling login attempts
    with valid or invalid usernames. An unauthenticated,
    remote attacker can exploit this to enumerate valid
    user accounts. This issue only affects versions 6.1.x,
    7.0.x, and 8.0.x. (CVE-2017-7945)

  - A denial of service vulnerability exists in the firewall
    when handling stale responses to authentication requests
    prior to selecting CHAP or PAP as the protocol. An
    unauthenticated, remote attacker can exploit this to
    cause the authentication process (authd) to stop
    responding. This issue only affects versions 7.0.x and
    7.1.x.

  - An information disclosure vulnerability exists when
    viewing changes in the configuration log due to the
    'Auth Password' and 'Priv Password' for the SNMPv3
    server profile not being properly masked. A local
    attacker can exploit this to disclose password
    information. This issue only affects versions 7.1.x and
    8.0.x.

  - A denial of service vulnerability exists due to a flaw
    when handling HA3 messages. An unauthenticated, remote
    attacker can exploit this to cause several processes to
    stop. This issue only affects version 7.1.x.
");
  # https://www.paloaltonetworks.com/documentation/80/pan-os/pan-os-release-notes/pan-os-8-0-2-addressed-issues
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d96265b");
  # https://www.paloaltonetworks.com/documentation/80/pan-os/pan-os-release-notes/pan-os-8-0-1-addressed-issues
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f083775");
  # https://www.paloaltonetworks.com/documentation/80/pan-os/pan-os-release-notes/pan-os-8-0-0-addressed-issues
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aacbe40b");
  # https://www.paloaltonetworks.com/documentation/71/pan-os/pan-os-release-notes/pan-os-7-1-10-addressed-issues
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?49c666f2");
  # https://www.paloaltonetworks.com/documentation/70/pan-os/pan-os-release-notes/pan-os-7-0-15-addressed-issues
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fe505ba3");
  # https://www.paloaltonetworks.com/documentation/61/pan-os/pan-os-release-notes/pan-os-6-1-17-addressed-issues
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9254ef1a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 6.1.17 / 7.0.15 /
7.1.10 / 8.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version");

  exit(0);
}

include("vcf.inc");

app_name = "Palo Alto Networks PAN-OS";

app_info = vcf::get_app_info(app:app_name, kb_ver:"Host/Palo_Alto/Firewall/Full_Version", webapp:true);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {"min_version" : "8.0.0", "max_version" : "8.0.1",  "fixed_version" : "8.0.2"  },
  {"min_version" : "7.1.0", "max_version" : "7.1.9",  "fixed_version" : "7.1.10" },
  {"min_version" : "7.0.0", "max_version" : "7.0.14", "fixed_version" : "7.0.15" },
  {"min_version" : "6.1.0", "max_version" : "6.1.16", "fixed_version" : "6.1.17" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:true});

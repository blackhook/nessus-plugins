#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2022-249-02. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164798);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/04");

  script_cve_id(
    "CVE-2022-3032",
    "CVE-2022-3033",
    "CVE-2022-3034",
    "CVE-2022-36059"
  );

  script_name(english:"Slackware Linux 15.0 / current mozilla-thunderbird  Multiple Vulnerabilities (SSA:2022-249-02)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to mozilla-thunderbird.");
  script_set_attribute(attribute:"description", value:
"The version of mozilla-thunderbird installed on the remote host is prior to 102.2.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the SSA:2022-249-02 advisory.

  - When receiving an HTML email that contained an <code>iframe</code> element, which used a
    <code>srcdoc</code> attribute to define the inner HTML document, remote objects specified in the nested
    document, for example images or videos, were not blocked. Rather, the network was accessed, the objects
    were loaded and displayed.  (CVE-2022-3032)

  - If a Thunderbird user replied to a crafted HTML email containing a <code>meta</code> tag, with the
    <code>meta</code> tag having the <code>http-equiv=refresh</code> attribute, and the content attribute
    specifying an URL, then Thunderbird started a network request to that URL, regardless of the configuration
    to block remote content. In combination with certain other HTML elements and attributes in the email, it
    was possible to execute JavaScript code included in the message in the context of the message compose
    document.  The JavaScript code was able to perform actions including, but probably not limited to, read
    and modify the contents of the message compose document, including the quoted original message, which
    could potentially contain the decrypted plaintext of encrypted data  in the crafted email. The contents
    could then be transmitted to the network, either to the URL specified in the META refresh tag, or to a
    different URL, as the JavaScript code could modify the URL specified in the document. This bug doesn't
    affect users who have changed the default Message Body display setting to 'simple html' or 'plain text'.
    (CVE-2022-3033)

  - When receiving an HTML email that specified to load an <code>iframe</code> element from a remote location,
    a request to the remote document was sent. However, Thunderbird didn't display the document.
    (CVE-2022-3034)

  - Thunderbird users who use the Matrix chat protocol were vulnerable to a denial-of-service attack. An
    adversary sharing a room with a user had the ability to carry out an attack against affected clients,
    making it not show all of a user's rooms or spaces and/or causing minor temporary corruption.
    (CVE-2022-36059)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected mozilla-thunderbird package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3033");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}

include("slackware.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);

var flag = 0;
var constraints = [
    { 'fixed_version' : '102.2.1', 'product' : 'mozilla-thunderbird', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i686' },
    { 'fixed_version' : '102.2.1', 'product' : 'mozilla-thunderbird', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '102.2.1', 'product' : 'mozilla-thunderbird', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i686' },
    { 'fixed_version' : '102.2.1', 'product' : 'mozilla-thunderbird', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
];

foreach constraint (constraints) {
    var pkg_arch = constraint['arch'];
    var arch = NULL;
    if (pkg_arch == "x86_64") {
        arch = pkg_arch;
    }
    if (slackware_check(osver:constraint['os_version'],
                        arch:arch,
                        pkgname:constraint['product'],
                        pkgver:constraint['fixed_version'],
                        pkgarch:pkg_arch,
                        pkgnum:constraint['service_pack'])) flag++;
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : slackware_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

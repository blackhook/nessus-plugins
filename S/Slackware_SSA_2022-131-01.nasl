##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2022-131-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161057);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/04");

  script_cve_id(
    "CVE-2022-27778",
    "CVE-2022-27779",
    "CVE-2022-27780",
    "CVE-2022-27781",
    "CVE-2022-27782",
    "CVE-2022-30115"
  );
  script_xref(name:"IAVA", value:"2022-A-0224-S");

  script_name(english:"Slackware Linux 14.0 / 14.1 / 14.2 / 15.0 / current curl  Multiple Vulnerabilities (SSA:2022-131-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to curl.");
  script_set_attribute(attribute:"description", value:
"The version of curl installed on the remote host is prior to 7.83.1. It is, therefore, affected by multiple
vulnerabilities as referenced in the SSA:2022-131-01 advisory.

  - libcurl would reuse a previously created connection even when a TLS or SSHrelated option had been changed
    that should have prohibited reuse.libcurl keeps previously used connections in a connection pool for
    subsequenttransfers to reuse if one of them matches the setup. However, several TLS andSSH settings were
    left out from the configuration match checks, making themmatch too easily. (CVE-2022-27782)

  - A use of incorrectly resolved name vulnerability fixed in 7.83.1 might remove the wrong file when `--no-
    clobber` is used together with `--remove-on-error`. (CVE-2022-27778)

  - libcurl wrongly allows cookies to be set for Top Level Domains (TLDs) if thehost name is provided with a
    trailing dot.curl can be told to receive and send cookies. curl's cookie engine can bebuilt with or
    without [Public Suffix List](https://publicsuffix.org/)awareness. If PSL support not provided, a more
    rudimentary check exists to atleast prevent cookies from being set on TLDs. This check was broken if
    thehost name in the URL uses a trailing dot.This can allow arbitrary sites to set cookies that then would
    get sent to adifferent and unrelated site or domain. (CVE-2022-27779)

  - The curl URL parser wrongly accepts percent-encoded URL separators like '/'when decoding the host name
    part of a URL, making it a *different* URL usingthe wrong host name when it is later retrieved.For
    example, a URL like `http://example.com%2F127.0.0.1/`, would be allowed bythe parser and get transposed
    into `http://example.com/127.0.0.1/`. This flawcan be used to circumvent filters, checks and more.
    (CVE-2022-27780)

  - libcurl provides the `CURLOPT_CERTINFO` option to allow applications torequest details to be returned
    about a server's certificate chain.Due to an erroneous function, a malicious server could make libcurl
    built withNSS get stuck in a never-ending busy-loop when trying to retrieve thatinformation.
    (CVE-2022-27781)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected curl package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27778");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    { 'fixed_version' : '7.83.1', 'product' : 'curl', 'os_name' : 'Slackware Linux', 'os_version' : '14.0', 'service_pack' : '1_slack14.0', 'arch' : 'i486' },
    { 'fixed_version' : '7.83.1', 'product' : 'curl', 'os_name' : 'Slackware Linux', 'os_version' : '14.0', 'service_pack' : '1_slack14.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '7.83.1', 'product' : 'curl', 'os_name' : 'Slackware Linux', 'os_version' : '14.1', 'service_pack' : '1_slack14.1', 'arch' : 'i486' },
    { 'fixed_version' : '7.83.1', 'product' : 'curl', 'os_name' : 'Slackware Linux', 'os_version' : '14.1', 'service_pack' : '1_slack14.1', 'arch' : 'x86_64' },
    { 'fixed_version' : '7.83.1', 'product' : 'curl', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '1_slack14.2', 'arch' : 'i586' },
    { 'fixed_version' : '7.83.1', 'product' : 'curl', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '1_slack14.2', 'arch' : 'x86_64' },
    { 'fixed_version' : '7.83.1', 'product' : 'curl', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '7.83.1', 'product' : 'curl', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '7.83.1', 'product' : 'curl', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '7.83.1', 'product' : 'curl', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
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
      severity   : SECURITY_WARNING,
      extra      : slackware_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

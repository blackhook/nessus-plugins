##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2022-179-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162585);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-32205",
    "CVE-2022-32206",
    "CVE-2022-32207",
    "CVE-2022-32208"
  );
  script_xref(name:"IAVA", value:"2022-A-0255-S");

  script_name(english:"Slackware Linux 14.0 / 14.1 / 14.2 / 15.0 / current curl  Multiple Vulnerabilities (SSA:2022-179-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to curl.");
  script_set_attribute(attribute:"description", value:
"The version of curl installed on the remote host is prior to 7.84.0. It is, therefore, affected by multiple
vulnerabilities as referenced in the SSA:2022-179-01 advisory.

  - When curl < 7.84.0 saves cookies, alt-svc and hsts data to local files, it makes the operation atomic by
    finalizing the operation with a rename from a temporary name to the final target file name.In that rename
    operation, it might accidentally *widen* the permissions for the target file, leaving the updated file
    accessible to more users than intended. (CVE-2022-32207)

  - A malicious server can serve excessive amounts of `Set-Cookie:` headers in a HTTP response to curl and
    curl < 7.84.0 stores all of them. A sufficiently large amount of (big) cookies make subsequent HTTP
    requests to this, or other servers to which the cookies match, create requests that become larger than the
    threshold that curl uses internally to avoid sending crazy large requests (1048576 bytes) and instead
    returns an error.This denial state might remain for as long as the same cookies are kept, match and
    haven't expired. Due to cookie matching rules, a server on `foo.example.com` can set cookies that also
    would match for `bar.example.com`, making it it possible for a sister server to effectively cause a
    denial of service for a sibling site on the same second level domain using this method. (CVE-2022-32205)

  - curl < 7.84.0 supports chained HTTP compression algorithms, meaning that a serverresponse can be
    compressed multiple times and potentially with different algorithms. The number of acceptable links in
    this decompression chain was unbounded, allowing a malicious server to insert a virtually unlimited
    number of compression steps.The use of such a decompression chain could result in a malloc bomb,
    makingcurl end up spending enormous amounts of allocated heap memory, or trying toand returning out of
    memory errors. (CVE-2022-32206)

  - When curl < 7.84.0 does FTP transfers secured by krb5, it handles message verification failures wrongly.
    This flaw makes it possible for a Man-In-The-Middle attack to go unnoticed and even allows it to inject
    data to the client. (CVE-2022-32208)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected curl package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32207");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/28");

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
    { 'fixed_version' : '7.84.0', 'product' : 'curl', 'os_name' : 'Slackware Linux', 'os_version' : '14.0', 'service_pack' : '1_slack14.0', 'arch' : 'i486' },
    { 'fixed_version' : '7.84.0', 'product' : 'curl', 'os_name' : 'Slackware Linux', 'os_version' : '14.0', 'service_pack' : '1_slack14.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '7.84.0', 'product' : 'curl', 'os_name' : 'Slackware Linux', 'os_version' : '14.1', 'service_pack' : '1_slack14.1', 'arch' : 'i486' },
    { 'fixed_version' : '7.84.0', 'product' : 'curl', 'os_name' : 'Slackware Linux', 'os_version' : '14.1', 'service_pack' : '1_slack14.1', 'arch' : 'x86_64' },
    { 'fixed_version' : '7.84.0', 'product' : 'curl', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '1_slack14.2', 'arch' : 'i586' },
    { 'fixed_version' : '7.84.0', 'product' : 'curl', 'os_name' : 'Slackware Linux', 'os_version' : '14.2', 'service_pack' : '1_slack14.2', 'arch' : 'x86_64' },
    { 'fixed_version' : '7.84.0', 'product' : 'curl', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '7.84.0', 'product' : 'curl', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '7.84.0', 'product' : 'curl', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '7.84.0', 'product' : 'curl', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
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

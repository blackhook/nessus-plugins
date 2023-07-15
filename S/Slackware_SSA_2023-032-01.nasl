#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2023-032-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170930);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id("CVE-2017-12613", "CVE-2021-35940", "CVE-2022-24963");

  script_name(english:"Slackware Linux 15.0 / current apr  Multiple Vulnerabilities (SSA:2023-032-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to apr.");
  script_set_attribute(attribute:"description", value:
"The version of apr installed on the remote host is prior to 1.7.2. It is, therefore, affected by multiple
vulnerabilities as referenced in the SSA:2023-032-01 advisory.

  - When apr_time_exp*() or apr_os_exp_time*() functions are invoked with an invalid month field value in
    Apache Portable Runtime APR 1.6.2 and prior, out of bounds memory may be accessed in converting this value
    to an apr_time_exp_t value, potentially revealing the contents of a different static heap value or
    resulting in program termination, and may represent an information disclosure or denial of service
    vulnerability to applications which call these APR functions with unvalidated external input.
    (CVE-2017-12613)

  - An out-of-bounds array read in the apr_time_exp*() functions was fixed in the Apache Portable Runtime
    1.6.3 release (CVE-2017-12613). The fix for this issue was not carried forward to the APR 1.7.x branch,
    and hence version 1.7.0 regressed compared to 1.6.3 and is vulnerable to the same issue. (CVE-2021-35940)

  - Integer Overflow or Wraparound vulnerability in apr_encode functions of Apache Portable Runtime (APR)
    allows an attacker to write beyond bounds of a buffer. This issue affects Apache Portable Runtime (APR)
    version 1.7.0. (CVE-2022-24963)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected apr package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35940");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-24963");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:apr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    { 'fixed_version' : '1.7.2', 'product' : 'apr', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '1.7.2', 'product' : 'apr', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '1.7.2', 'product' : 'apr', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '1.7.2', 'product' : 'apr', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
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
      severity   : SECURITY_NOTE,
      extra      : slackware_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

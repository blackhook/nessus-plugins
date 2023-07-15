#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2023-025-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170653);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/30");

  script_cve_id("CVE-2022-3094", "CVE-2022-3736", "CVE-2022-3924");
  script_xref(name:"IAVA", value:"2023-A-0058-S");

  script_name(english:"Slackware Linux 15.0 / current bind  Multiple Vulnerabilities (SSA:2023-025-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to bind.");
  script_set_attribute(attribute:"description", value:
"The version of bind installed on the remote host is prior to 9.16.37 / 9.18.11. It is, therefore, affected by multiple
vulnerabilities as referenced in the SSA:2023-025-01 advisory.

  - BIND 9 resolver can crash when stale cache and stale answers are enabled, option `stale-answer-client-
    timeout` is set to a positive integer, and the resolver receives an RRSIG query. This issue affects BIND 9
    versions 9.16.12 through 9.16.36, 9.18.0 through 9.18.10, 9.19.0 through 9.19.8, and 9.16.12-S1 through
    9.16.36-S1. (CVE-2022-3736)

  - Sending a flood of dynamic DNS updates may cause `named` to allocate large amounts of memory. This, in
    turn, may cause `named` to exit due to a lack of free memory. We are not aware of any cases where this has
    been exploited. Memory is allocated prior to the checking of access permissions (ACLs) and is retained
    during the processing of a dynamic update from a client whose access credentials are accepted. Memory
    allocated to clients that are not permitted to send updates is released immediately upon rejection. The
    scope of this vulnerability is limited therefore to trusted clients who are permitted to make dynamic zone
    changes. If a dynamic update is REFUSED, memory will be released again very quickly. Therefore it is only
    likely to be possible to degrade or stop `named` by sending a flood of unaccepted dynamic updates
    comparable in magnitude to a query flood intended to achieve the same detrimental outcome. BIND 9.11 and
    earlier branches are also affected, but through exhaustion of internal resources rather than memory
    constraints. This may reduce performance but should not be a significant problem for most servers.
    Therefore we don't intend to address this for BIND versions prior to BIND 9.16. This issue affects BIND 9
    versions 9.16.0 through 9.16.36, 9.18.0 through 9.18.10, 9.19.0 through 9.19.8, and 9.16.8-S1 through
    9.16.36-S1. (CVE-2022-3094)

  - This issue can affect BIND 9 resolvers with `stale-answer-enable yes;` that also make use of the option
    `stale-answer-client-timeout`, configured with a value greater than zero. If the resolver receives many
    queries that require recursion, there will be a corresponding increase in the number of clients that are
    waiting for recursion to complete. If there are sufficient clients already waiting when a new client query
    is received so that it is necessary to SERVFAIL the longest waiting client (see BIND 9 ARM `recursive-
    clients` limit and soft quota), then it is possible for a race to occur between providing a stale answer
    to this older client and sending an early timeout SERVFAIL, which may cause an assertion failure. This
    issue affects BIND 9 versions 9.16.12 through 9.16.36, 9.18.0 through 9.18.10, 9.19.0 through 9.19.8, and
    9.16.12-S1 through 9.16.36-S1. (CVE-2022-3924)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected bind package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3736");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:bind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    { 'fixed_version' : '9.16.37', 'product' : 'bind', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i586' },
    { 'fixed_version' : '9.16.37', 'product' : 'bind', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '9.18.11', 'product' : 'bind', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i586' },
    { 'fixed_version' : '9.18.11', 'product' : 'bind', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
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

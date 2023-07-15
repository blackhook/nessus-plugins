#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
#
# The descriptive text and package checks in this plugin were
# extracted from Slackware Security Advisory SSA:2023-130-01. The text
# itself is copyright (C) Slackware Linux, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175569);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/09");

  script_cve_id(
    "CVE-2023-32206",
    "CVE-2023-32207",
    "CVE-2023-32211",
    "CVE-2023-32212",
    "CVE-2023-32213",
    "CVE-2023-32214",
    "CVE-2023-32215"
  );

  script_name(english:"Slackware Linux 15.0 / current mozilla-thunderbird  Multiple Vulnerabilities (SSA:2023-130-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware Linux host is missing a security update to mozilla-thunderbird.");
  script_set_attribute(attribute:"description", value:
"The version of mozilla-thunderbird installed on the remote host is prior to 102.11.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the SSA:2023-130-01 advisory.

  - An out-of-bound read could have led to a crash in the RLBox Expat driver.  (CVE-2023-32206)

  - A missing delay in popup notifications could have made it possible for an attacker to trick a user into
    granting permissions.  (CVE-2023-32207)

  - A type checking bug would have led to invalid code being compiled.  (CVE-2023-32211)

  - An attacker could have positioned a <code>datalist</code> element to obscure the address bar.
    (CVE-2023-32212)

  - When reading a file, an uninitialized value could have been used as read limit.  (CVE-2023-32213)

  - Protocol handlers <code>ms-cxh</code> and <code>ms-cxh-full</code> could have been leveraged to trigger a
    denial of service. Note: This attack only affects Windows. Other operating systems are not affected.
    (CVE-2023-32214)

  - Mozilla developers and community members Gabriele Svelto, Andrew Osmond, Emily McDonough, Sebastian
    Hengst, Andrew McCreight and the Mozilla Fuzzing Team reported memory safety bugs present in Thunderbird
    102.10. Some of these bugs showed evidence of memory corruption and we presume that with enough effort
    some of these could have been exploited to run arbitrary code.  (CVE-2023-32215)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected mozilla-thunderbird package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32215");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-thunderbird");
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
    { 'fixed_version' : '102.11.0', 'product' : 'mozilla-thunderbird', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'i686' },
    { 'fixed_version' : '102.11.0', 'product' : 'mozilla-thunderbird', 'os_name' : 'Slackware Linux', 'os_version' : '15.0', 'service_pack' : '1_slack15.0', 'arch' : 'x86_64' },
    { 'fixed_version' : '102.11.0', 'product' : 'mozilla-thunderbird', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'i686' },
    { 'fixed_version' : '102.11.0', 'product' : 'mozilla-thunderbird', 'os_name' : 'Slackware Linux', 'os_version' : 'current', 'service_pack' : '1', 'arch' : 'x86_64' }
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

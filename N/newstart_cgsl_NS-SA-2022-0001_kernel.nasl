##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0001. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160776);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2017-2647", "CVE-2017-12192", "CVE-2020-10711");

  script_name(english:"NewStart CGSL MAIN 4.05 : kernel Multiple Vulnerabilities (NS-SA-2022-0001)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has kernel packages installed that are affected by multiple
vulnerabilities:

  - The keyctl_read_key function in security/keys/keyctl.c in the Key Management subcomponent in the Linux
    kernel before 4.13.5 does not properly consider that a key may be possessed but negatively instantiated,
    which allows local users to cause a denial of service (OOPS and system crash) via a crafted KEYCTL_READ
    operation. (CVE-2017-12192)

  - The KEYS subsystem in the Linux kernel before 3.18 allows local users to gain privileges or cause a denial
    of service (NULL pointer dereference and system crash) via vectors involving a NULL value for a certain
    match field, related to the keyring_search_iterator function in keyring.c. (CVE-2017-2647)

  - A NULL pointer dereference flaw was found in the Linux kernel's SELinux subsystem in versions before 5.7.
    This flaw occurs while importing the Commercial IP Security Option (CIPSO) protocol's category bitmap into
    the SELinux extensible bitmap via the' ebitmap_netlbl_import' routine. While processing the CIPSO
    restricted bitmap tag in the 'cipso_v4_parsetag_rbm' routine, it sets the security attribute to indicate
    that the category bitmap is present, even if it has not been allocated. This issue leads to a NULL pointer
    dereference issue while importing the same category bitmap into SELinux. This flaw allows a remote network
    user to crash the system kernel, resulting in a denial of service. (CVE-2020-10711)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0001");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2017-12192");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2017-2647");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-10711");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-2647");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:4");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 4.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 4.05': [
    'kernel-2.6.32-642.13.1.el6.cgslv4_5.0.161.gc808dd6',
    'kernel-debuginfo-2.6.32-642.13.1.el6.cgslv4_5.0.161.gc808dd6',
    'kernel-debuginfo-common-x86_64-2.6.32-642.13.1.el6.cgslv4_5.0.161.gc808dd6',
    'kernel-devel-2.6.32-642.13.1.el6.cgslv4_5.0.161.gc808dd6',
    'kernel-headers-2.6.32-642.13.1.el6.cgslv4_5.0.161.gc808dd6',
    'perf-2.6.32-642.13.1.el6.cgslv4_5.0.161.gc808dd6',
    'perf-debuginfo-2.6.32-642.13.1.el6.cgslv4_5.0.161.gc808dd6',
    'python-perf-2.6.32-642.13.1.el6.cgslv4_5.0.161.gc808dd6',
    'python-perf-debuginfo-2.6.32-642.13.1.el6.cgslv4_5.0.161.gc808dd6'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel');
}

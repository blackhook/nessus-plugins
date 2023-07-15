#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0111. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154575);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/11");

  script_cve_id("CVE-2021-25217");
  script_xref(name:"IAVB", value:"2021-B-0032-S");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : dhcp Vulnerability (NS-SA-2021-0111)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has dhcp packages installed that are affected by a
vulnerability:

  - In ISC DHCP 4.1-ESV-R1 -> 4.1-ESV-R16, ISC DHCP 4.4.0 -> 4.4.2 (Other branches of ISC DHCP (i.e., releases
    in the 4.0.x series or lower and releases in the 4.3.x series) are beyond their End-of-Life (EOL) and no
    longer supported by ISC. From inspection it is clear that the defect is also present in releases from
    those series, but they have not been officially tested for the vulnerability), The outcome of encountering
    the defect while reading a lease that will trigger it varies, according to: the component being affected
    (i.e., dhclient or dhcpd) whether the package was built as a 32-bit or 64-bit binary whether the compiler
    flag -fstack-protection-strong was used when compiling In dhclient, ISC has not successfully reproduced
    the error on a 64-bit system. However, on a 32-bit system it is possible to cause dhclient to crash when
    reading an improper lease, which could cause network connectivity problems for an affected system due to
    the absence of a running DHCP client process. In dhcpd, when run in DHCPv4 or DHCPv6 mode: if the dhcpd
    server binary was built for a 32-bit architecture AND the -fstack-protection-strong flag was specified to
    the compiler, dhcpd may exit while parsing a lease file containing an objectionable lease, resulting in
    lack of service to clients. Additionally, the offending lease and the lease immediately following it in
    the lease database may be improperly deleted. if the dhcpd server binary was built for a 64-bit
    architecture OR if the -fstack-protection-strong compiler flag was NOT specified, the crash will not
    occur, but it is possible for the offending lease and the lease which immediately followed it to be
    improperly deleted. (CVE-2021-25217)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0111");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-25217");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL dhcp packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25217");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:dhclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:dhcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:dhcp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dhclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dhcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:dhcp-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'dhclient-4.2.5-83.el7_9.1.cgslv5.0.5.g4daf79e',
    'dhcp-4.2.5-83.el7_9.1.cgslv5.0.5.g4daf79e',
    'dhcp-common-4.2.5-83.el7_9.1.cgslv5.0.5.g4daf79e',
    'dhcp-debuginfo-4.2.5-83.el7_9.1.cgslv5.0.5.g4daf79e',
    'dhcp-devel-4.2.5-83.el7_9.1.cgslv5.0.5.g4daf79e',
    'dhcp-libs-4.2.5-83.el7_9.1.cgslv5.0.5.g4daf79e'
  ],
  'CGSL MAIN 5.04': [
    'dhclient-4.2.5-83.el7_9.1.cgslv5.0.5.g4daf79e',
    'dhcp-4.2.5-83.el7_9.1.cgslv5.0.5.g4daf79e',
    'dhcp-common-4.2.5-83.el7_9.1.cgslv5.0.5.g4daf79e',
    'dhcp-debuginfo-4.2.5-83.el7_9.1.cgslv5.0.5.g4daf79e',
    'dhcp-devel-4.2.5-83.el7_9.1.cgslv5.0.5.g4daf79e',
    'dhcp-libs-4.2.5-83.el7_9.1.cgslv5.0.5.g4daf79e'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dhcp');
}

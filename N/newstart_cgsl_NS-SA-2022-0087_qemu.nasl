#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0087. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167503);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/15");

  script_cve_id("CVE-2019-15890", "CVE-2020-1711", "CVE-2020-14364");
  script_xref(name:"IAVB", value:"2020-B-0063-S");

  script_name(english:"NewStart CGSL MAIN 6.02 : qemu Multiple Vulnerabilities (NS-SA-2022-0087)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has qemu packages installed that are affected by multiple
vulnerabilities:

  - libslirp 4.0.0, as used in QEMU 4.1.0, has a use-after-free in ip_reass in ip_input.c. (CVE-2019-15890)

  - An out-of-bounds read/write access flaw was found in the USB emulator of the QEMU in versions before
    5.2.0. This issue occurs while processing USB packets from a guest when USBDevice 'setup_len' exceeds its
    'data_buf[4096]' in the do_token_in, do_token_out routines. This flaw allows a guest user to crash the
    QEMU process, resulting in a denial of service, or the potential execution of arbitrary code with the
    privileges of the QEMU process on the host. (CVE-2020-14364)

  - An out-of-bounds heap buffer access flaw was found in the way the iSCSI Block driver in QEMU versions
    2.12.0 before 4.2.1 handled a response coming from an iSCSI server while checking the status of a Logical
    Address Block (LBA) in an iscsi_co_block_status() routine. A remote user could use this flaw to crash the
    QEMU process, resulting in a denial of service or potential execution of arbitrary code with privileges of
    the QEMU process on the host. (CVE-2020-1711)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0087");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-15890");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-14364");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-1711");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL qemu packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1711");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'qemu-4.1.0-2.el8.cgslv6_2.244.g1a4f40fbc',
    'qemu-block-rbd-4.1.0-2.el8.cgslv6_2.244.g1a4f40fbc',
    'qemu-common-4.1.0-2.el8.cgslv6_2.244.g1a4f40fbc',
    'qemu-img-4.1.0-2.el8.cgslv6_2.244.g1a4f40fbc',
    'qemu-kvm-4.1.0-2.el8.cgslv6_2.244.g1a4f40fbc',
    'qemu-tools-4.1.0-2.el8.cgslv6_2.244.g1a4f40fbc'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu');
}

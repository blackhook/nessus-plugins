##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0073. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147295);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-10722",
    "CVE-2020-10723",
    "CVE-2020-10725",
    "CVE-2020-10726"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"NewStart CGSL MAIN 6.02 : dpdk Multiple Vulnerabilities (NS-SA-2021-0073)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has dpdk packages installed that are affected by multiple
vulnerabilities:

  - A flaw was found in DPDK version 19.11 and above that allows a malicious guest to cause a segmentation
    fault of the vhost-user backend application running on the host, which could result in a loss of
    connectivity for the other guests running on that host. This is caused by a missing validity check of the
    descriptor address in the function `virtio_dev_rx_batch_packed()`. (CVE-2020-10725)

  - A vulnerability was found in DPDK versions 19.11 and above. A malicious container that has direct access
    to the vhost-user socket can keep sending VHOST_USER_GET_INFLIGHT_FD messages, causing a resource leak
    (file descriptors and virtual memory), which may result in a denial of service. (CVE-2020-10726)

  - A vulnerability was found in DPDK versions 18.05 and above. A missing check for an integer overflow in
    vhost_user_set_log_base() could result in a smaller memory map than requested, possibly allowing memory
    corruption. (CVE-2020-10722)

  - A memory corruption issue was found in DPDK versions 17.05 and above. This flaw is caused by an integer
    truncation on the index of a payload. Under certain circumstances, the index (a UInt) is copied and
    truncated into a uint16, which can lead to out of bound indexing and possible memory corruption.
    (CVE-2020-10723)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0073");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL dpdk packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10723");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL MAIN 6.02': [
    'dpdk-19.11.3-1.el8',
    'dpdk-debuginfo-19.11.3-1.el8',
    'dpdk-debugsource-19.11.3-1.el8',
    'dpdk-devel-19.11.3-1.el8',
    'dpdk-devel-debuginfo-19.11.3-1.el8',
    'dpdk-doc-19.11.3-1.el8',
    'dpdk-tools-19.11.3-1.el8'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dpdk');
}

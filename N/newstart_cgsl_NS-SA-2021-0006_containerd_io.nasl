##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0006. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147293);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-5736",
    "CVE-2019-9512",
    "CVE-2019-9514",
    "CVE-2019-9515",
    "CVE-2019-16884"
  );
  script_bugtraq_id(106976);
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : containerd.io Multiple Vulnerabilities (NS-SA-2021-0006)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has containerd.io packages installed that are
affected by multiple vulnerabilities:

  - runc through 1.0.0-rc8, as used in Docker through 19.03.2-ce and other products, allows AppArmor
    restriction bypass because libcontainer/rootfs_linux.go incorrectly checks mount targets, and thus a
    malicious Docker image can mount over a /proc directory. (CVE-2019-16884)

  - runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite
    the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a
    command as root within one of these types of containers: (1) a new container with an attacker-controlled
    image, or (2) an existing container, to which the attacker previously had write access, that can be
    attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe.
    (CVE-2019-5736)

  - Some HTTP/2 implementations are vulnerable to ping floods, potentially leading to a denial of service. The
    attacker sends continual pings to an HTTP/2 peer, causing the peer to build an internal queue of
    responses. Depending on how efficiently this data is queued, this can consume excess CPU, memory, or both.
    (CVE-2019-9512)

  - Some HTTP/2 implementations are vulnerable to a reset flood, potentially leading to a denial of service.
    The attacker opens a number of streams and sends an invalid request over each stream that should solicit a
    stream of RST_STREAM frames from the peer. Depending on how the peer queues the RST_STREAM frames, this
    can consume excess memory, CPU, or both. (CVE-2019-9514)

  - Some HTTP/2 implementations are vulnerable to a settings flood, potentially leading to a denial of
    service. The attacker sends a stream of SETTINGS frames to the peer. Since the RFC requires that the peer
    reply with one acknowledgement per SETTINGS frame, an empty SETTINGS frame is almost equivalent in
    behavior to a ping. Depending on how efficiently this data is queued, this can consume excess CPU, memory,
    or both. (CVE-2019-9515)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0006");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL containerd.io packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5736");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Docker Container Escape Via runC Overwrite');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/08");
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

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL CORE 5.04': [
    'containerd.io-1.2.13-1.el7.200814164614git76a9926'
  ],
  'CGSL MAIN 5.04': [
    'containerd.io-1.2.13-1.el7.200814164614git76a9926'
  ]
};
pkg_list = pkgs[release];

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'containerd.io');
}

#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0138. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154519);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/28");

  script_cve_id(
    "CVE-2017-14992",
    "CVE-2017-16539",
    "CVE-2017-18367",
    "CVE-2018-10892",
    "CVE-2018-15664",
    "CVE-2018-20699",
    "CVE-2019-5736",
    "CVE-2019-13139",
    "CVE-2019-13509",
    "CVE-2020-13401"
  );

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : docker-ce Multiple Vulnerabilities (NS-SA-2021-0138)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has docker-ce packages installed that are affected
by multiple vulnerabilities:

  - Lack of content verification in Docker-CE (Also known as Moby) versions 1.12.6-0, 1.10.3, 17.03.0,
    17.03.1, 17.03.2, 17.06.0, 17.06.1, 17.06.2, 17.09.0, and earlier allows a remote attacker to cause a
    Denial of Service via a crafted image layer payload, aka gzip bombing. (CVE-2017-14992)

  - The DefaultLinuxSpec function in oci/defaults.go in Docker Moby through 17.03.2-ce does not block
    /proc/scsi pathnames, which allows attackers to trigger data loss (when certain older Linux kernels are
    used) by leveraging Docker container access to write a scsi remove-single-device line to
    /proc/scsi/scsi, aka SCSI MICDROP. (CVE-2017-16539)

  - libseccomp-golang 0.9.0 and earlier incorrectly generates BPFs that OR multiple arguments rather than
    ANDing them. A process running under a restrictive seccomp filter that specified multiple syscall
    arguments could bypass intended access restrictions by specifying a single matching argument.
    (CVE-2017-18367)

  - The default OCI linux spec in oci/defaults{_linux}.go in Docker/Moby from 1.11 to current does not block
    /proc/acpi pathnames. The flaw allows an attacker to modify host's hardware like enabling/disabling
    bluetooth or turning up/down keyboard brightness. (CVE-2018-10892)

  - In Docker through 18.06.1-ce-rc2, the API endpoints behind the 'docker cp' command are vulnerable to a
    symlink-exchange attack with Directory Traversal, giving attackers arbitrary read-write access to the host
    filesystem with root privileges, because daemon/archive.go does not do archive operations on a frozen
    filesystem (or from within a chroot). (CVE-2018-15664)

  - Docker Engine before 18.09 allows attackers to cause a denial of service (dockerd memory consumption) via
    a large integer in a --cpuset-mems or --cpuset-cpus value, related to daemon/daemon_unix.go,
    pkg/parsers/parsers.go, and pkg/sysinfo/sysinfo.go. (CVE-2018-20699)

  - In Docker before 18.09.4, an attacker who is capable of supplying or manipulating the build path for the
    docker build command would be able to gain command execution. An issue exists in the way docker build
    processes remote git URLs, and results in command injection into the underlying git clone command,
    leading to code execution in the context of the user executing the docker build command. This occurs
    because git ref can be misinterpreted as a flag. (CVE-2019-13139)

  - In Docker CE and EE before 18.09.8 (as well as Docker EE before 17.06.2-ee-23 and 18.x before
    18.03.1-ee-10), Docker Engine in debug mode may sometimes add secrets to the debug log. This applies to a
    scenario where docker stack deploy is run to redeploy a stack that includes (non external) secrets. It
    potentially applies to other API users of the stack API if they resend the secret. (CVE-2019-13509)

  - runc through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite
    the host runc binary (and consequently obtain host root access) by leveraging the ability to execute a
    command as root within one of these types of containers: (1) a new container with an attacker-controlled
    image, or (2) an existing container, to which the attacker previously had write access, that can be
    attached with docker exec. This occurs because of file-descriptor mishandling, related to /proc/self/exe.
    (CVE-2019-5736)

  - An issue was discovered in Docker Engine before 19.03.11. An attacker in a container, with the CAP_NET_RAW
    capability, can craft IPv6 router advertisements, and consequently spoof external IPv6 hosts, obtain
    sensitive information, or cause a denial of service. (CVE-2020-13401)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0138");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2017-14992");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2017-16539");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2017-18367");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-10892");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-15664");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-20699");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-13139");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-13509");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-5736");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-13401");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL docker-ce packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:docker-ce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:docker-ce-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:docker-ce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:docker-ce-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'docker-ce-17.03.3-1.el7.2009070756git3409267',
    'docker-ce-debuginfo-17.03.3-1.el7.2009070756git3409267'
  ],
  'CGSL MAIN 5.05': [
    'docker-ce-17.03.3-1.el7.2009070756git3409267',
    'docker-ce-debuginfo-17.03.3-1.el7.2009070756git3409267'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'docker-ce');
}

#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(146252);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/09");

  script_cve_id(
    "CVE-2020-15257"
  );

  script_name(english:"EulerOS 2.0 SP9 : kata-containers (EulerOS-SA-2021-1245)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the kata-containers package installed,
the EulerOS installation on the remote host is affected by the
following vulnerability :

  - containerd is an industry-standard container runtime
    and is available as a daemon for Linux and Windows. In
    containerd before versions 1.3.9 and 1.4.3, the
    containerd-shim API is improperly exposed to host
    network containers. Access controls for the shim's API
    socket verified that the connecting process had an
    effective UID of 0, but did not otherwise restrict
    access to the abstract Unix domain socket. This would
    allow malicious containers running in the same network
    namespace as the shim, with an effective UID of 0 but
    otherwise reduced privileges, to cause new processes to
    be run with elevated privileges. This vulnerability has
    been fixed in containerd 1.3.9 and 1.4.3. Users should
    update to these versions as soon as they are released.
    It should be noted that containers started with an old
    version of containerd-shim should be stopped and
    restarted, as running containers will continue to be
    vulnerable even after an upgrade. If you are not
    providing the ability for untrusted users to start
    containers in the same network namespace as the shim
    (typically the 'host' network namespace, for example
    with docker run --net=host or hostNetwork: true in a
    Kubernetes pod) and run with an effective UID of 0, you
    are not vulnerable to this issue. If you are running
    containers with a vulnerable configuration, you can
    deny access to all abstract sockets with AppArmor by
    adding a line similar to deny unix addr=@**, to your
    policy. It is best practice to run containers with a
    reduced set of privileges, with a non-zero UID, and
    with isolated namespaces. The containerd maintainers
    strongly advise against sharing namespaces with the
    host. Reducing the set of isolation mechanisms used for
    a container necessarily increases that container's
    privilege, regardless of what container runtime is used
    for running that container.(CVE-2020-15257)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1245
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15b50a4d");
  script_set_attribute(attribute:"solution", value:
"Update the affected kata-containers package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kata-containers");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(9)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["kata-containers-v1.11.1-6.h13.eulerosv2r9"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"9", reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kata-containers");
}

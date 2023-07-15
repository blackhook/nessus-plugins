#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2021-4.0-0095. The text
# itself is copyright (C) VMware, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153035);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2021-37576", "CVE-2021-38166");

  script_name(english:"Photon OS 4.0: Linux PHSA-2021-4.0-0095");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the linux package has been released.

  - arch/powerpc/kvm/book3s_rtas.c in the Linux kernel through 5.13.5 on the powerpc platform allows KVM guest
    OS users to cause host OS memory corruption via rtas_args.nargs, aka CID-f62f3c20647e. (CVE-2021-37576)

  - In kernel/bpf/hashtab.c in the Linux kernel through 5.13.8, there is an integer overflow and out-of-bounds
    write when many elements are placed in a single bucket. NOTE: exploitation might be impractical without
    the CAP_SYS_ADMIN capability. (CVE-2021-38166)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Updates-4.0-95.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37576");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:4.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"PhotonOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/PhotonOS/release", "Host/PhotonOS/rpm-list");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/PhotonOS/release');
if (isnull(release) || release !~ "^VMware Photon") audit(AUDIT_OS_NOT, 'PhotonOS');
if (release !~ "^VMware Photon (?:Linux|OS) 4\.0(\D|$)") audit(AUDIT_OS_NOT, 'PhotonOS 4.0');

if (!get_kb_item('Host/PhotonOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'PhotonOS', cpu);

var flag = 0;

if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-5.10.61-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', reference:'linux-api-headers-5.10.61-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-aws-5.10.61-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-aws-devel-5.10.61-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-aws-docs-5.10.61-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-aws-drivers-gpu-5.10.61-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-aws-oprofile-5.10.61-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-aws-sound-5.10.61-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-devel-5.10.61-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-docs-5.10.61-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-drivers-gpu-5.10.61-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-drivers-intel-sgx-5.10.61-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-drivers-sound-5.10.61-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-esx-5.10.61-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-esx-devel-5.10.61-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-esx-docs-5.10.61-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-oprofile-5.10.61-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-python3-perf-5.10.61-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-rt-5.10.61-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-rt-devel-5.10.61-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-rt-docs-5.10.61-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-secure-5.10.61-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-secure-devel-5.10.61-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-secure-docs-5.10.61-1.ph4')) flag++;
if (rpm_check(release:'PhotonOS-4.0', cpu:'x86_64', reference:'linux-tools-5.10.61-1.ph4')) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux');
}

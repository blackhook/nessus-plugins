#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0099. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127325);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2017-2636",
    "CVE-2017-7645",
    "CVE-2017-7895",
    "CVE-2017-1000364",
    "CVE-2017-1000366"
  );
  script_bugtraq_id(98085);

  script_name(english:"NewStart CGSL MAIN 4.05 : kernel Multiple Vulnerabilities (NS-SA-2019-0099)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has kernel packages installed that are affected by multiple
vulnerabilities:

  - A flaw was found in the way memory was being allocated
    on the stack for user space binaries. If heap (or
    different memory region) and stack memory regions were
    adjacent to each other, an attacker could use this flaw
    to jump over the stack guard gap, cause controlled
    memory corruption on process stack or the adjacent
    memory region, and thus increase their privileges on the
    system. This is a kernel-side mitigation which increases
    the stack guard gap size from one page to 1 MiB to make
    successful exploitation of this issue more difficult.
    (CVE-2017-1000364)

  - A flaw was found in the way memory was being allocated
    on the stack for user space binaries. If heap (or
    different memory region) and stack memory regions were
    adjacent to each other, an attacker could use this flaw
    to jump over the stack guard gap, cause controlled
    memory corruption on process stack or the adjacent
    memory region, and thus increase their privileges on the
    system. This is glibc-side mitigation which blocks
    processing of LD_LIBRARY_PATH for programs running in
    secure-execution mode and reduces the number of
    allocations performed by the processing of LD_AUDIT,
    LD_PRELOAD, and LD_HWCAP_MASK, making successful
    exploitation of this issue more difficult.
    (CVE-2017-1000366)

  - A race condition flaw was found in the N_HLDC Linux
    kernel driver when accessing n_hdlc.tbuf list that can
    lead to double free. A local, unprivileged user able to
    set the HDLC line discipline on the tty device could use
    this flaw to increase their privileges on the system.
    (CVE-2017-2636)

  - The NFS2/3 RPC client could send long arguments to the
    NFS server. These encoded arguments are stored in an
    array of memory pages, and accessed using pointer
    variables. Arbitrarily long arguments could make these
    pointers point outside the array and cause an out-of-
    bounds memory access. A remote user or program could use
    this flaw to crash the kernel, resulting in denial of
    service. (CVE-2017-7645)

  - The NFSv2 and NFSv3 server implementations in the Linux
    kernel through 4.10.13 lacked certain checks for the end
    of a buffer. A remote attacker could trigger a pointer-
    arithmetic error or possibly cause other unspecified
    impacts using crafted requests related to
    fs/nfsd/nfs3xdr.c and fs/nfsd/nfsxdr.c. (CVE-2017-7895)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0099");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7895");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Solaris RSH Stack Clash Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL MAIN 4.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.05": [
    "kernel-2.6.32-642.13.1.el6.cgsl7442",
    "kernel-abi-whitelists-2.6.32-642.13.1.el6.cgsl7259",
    "kernel-debug-2.6.32-642.13.1.el6.cgsl7259",
    "kernel-debug-devel-2.6.32-642.13.1.el6.cgsl7259",
    "kernel-devel-2.6.32-642.13.1.el6.cgsl7442",
    "kernel-doc-2.6.32-642.13.1.el6.cgsl7259",
    "kernel-firmware-2.6.32-642.13.1.el6.cgsl7442",
    "kernel-headers-2.6.32-642.13.1.el6.cgsl7442",
    "perf-2.6.32-642.13.1.el6.cgsl7259"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}

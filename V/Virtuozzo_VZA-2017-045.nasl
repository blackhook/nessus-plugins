#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100601);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2017-8890",
    "CVE-2017-9074",
    "CVE-2017-9075",
    "CVE-2017-9076",
    "CVE-2017-9077"
  );

  script_name(english:"Virtuozzo 7 : readykernel-patch (VZA-2017-045)");
  script_summary(english:"Checks the readykernel output for the updated patch.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the vzkernel package and the
readykernel-patch installed, the Virtuozzo installation on the remote
host is affected by the following vulnerabilities :

  - The tcp_v6_syn_recv_sock function in
    net/ipv6/tcp_ipv6.c in the Linux kernel mishandles
    inheritance, which allows local users to cause a denial
    of service or possibly have unspecified other impact
    via crafted system calls, a related issue to
    CVE-2017-8890. An unprivileged local user could use
    this flaw to induce kernel memory corruption on the
    system, leading to a crash. Due to the nature of the
    flaw, privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.

  - The IPv6 DCCP implementation in the Linux kernel
    mishandles inheritance, which allows local users to
    cause a denial of service or possibly have unspecified
    other impact via crafted system calls, a related issue
    to CVE-2017-8890. An unprivileged local user could use
    this flaw to induce kernel memory corruption on the
    system, leading to a crash. Due to the nature of the
    flaw, privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.

  - The sctp_v6_create_accept_sk function in
    net/sctp/ipv6.c in the Linux kernel mishandles
    inheritance, which allows local users to cause a denial
    of service or possibly have unspecified other impact
    via crafted system calls, a related issue to
    CVE-2017-8890. An unprivileged local user could use
    this flaw to induce kernel memory corruption on the
    system, leading to a crash. Due to the nature of the
    flaw, privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.

  - The IPv6 fragmentation implementation in the Linux
    kernel through 4.11.1 does not consider that the
    nexthdr field may be associated with an invalid option,
    which allows local users to cause a denial of service
    (out-of-bounds read and BUG) or possibly have
    unspecified other impact via crafted socket and send
    system calls.

  - The inet_csk_clone_lock function in
    net/ipv4/inet_connection_sock.c in the Linux kernel
    allows attackers to cause a denial of service (double
    free) or possibly have unspecified other impact by
    leveraging use of the accept system call. An
    unprivileged local user could use this flaw to induce
    kernel memory corruption on the system, leading to a
    crash. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out, although we
    believe it is unlikely.

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://help.virtuozzo.com/customer/portal/articles/2816867");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-30.10-21.0-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a0bddd6");
  script_set_attribute(attribute:"solution", value:"Update the readykernel patch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:readykernel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Virtuozzo/release", "Host/Virtuozzo/rpm-list", "Host/readykernel-info");

  exit(0);
}

include("global_settings.inc");
include("readykernel.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Virtuozzo/release");
if (isnull(release) || "Virtuozzo" >!< release) audit(AUDIT_OS_NOT, "Virtuozzo");
os_ver = pregmatch(pattern: "Virtuozzo Linux release ([0-9]+\.[0-9])(\D|$)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 7.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

rk_info = get_kb_item("Host/readykernel-info");
if (empty_or_null(rk_info)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");

checks = make_list2(
  make_array(
    "kernel","vzkernel-3.10.0-514.16.1.vz7.30.10",
    "patch","readykernel-patch-30.10-21.0-1.vl7"
  )
);
readykernel_execute_checks(checks:checks, severity:SECURITY_HOLE, release:"Virtuozzo-7");

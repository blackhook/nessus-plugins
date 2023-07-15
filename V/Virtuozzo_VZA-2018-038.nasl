#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110311);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2017-17448",
    "CVE-2017-17449",
    "CVE-2017-17450",
    "CVE-2017-17807",
    "CVE-2018-1130",
    "CVE-2018-5803"
  );

  script_name(english:"Virtuozzo 7 : readykernel-patch (VZA-2018-038)");
  script_summary(english:"Checks the readykernel output for the updated patch.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the vzkernel package and the
readykernel-patch installed, the Virtuozzo installation on the remote
host is affected by the following vulnerabilities :

  - Linux kernel before version 4.16-rc7 is vulnerable to a
    null pointer dereference in dccp_write_xmit() function
    in net/dccp/output.c in that allows a local user to
    cause a denial of service by a number of certain
    crafted system calls.

  - It was found that _sctp_make_chunk() function did not
    check if the chunk length for INIT and INIT_ACK packets
    was within the allowed limits. A local attacker could
    exploit this to trigger a kernel crash.

  - It was discovered that nfnl_cthelper_list structure was
    accessible to any user with CAP_NET_ADMIN capability in
    a network namespace. An unprivileged local user could
    exploit that to affect netfilter conntrack helpers on
    the host.

  - It was discovered that a nlmon link inside a child
    network namespace was not restricted to that namespace.
    An unprivileged local user could exploit that to
    monitor system-wide netlink activity.

  - The KEYS subsystem in the Linux kernel omitted an
    access-control check when writing a key to the current
    task's default keyring, allowing a local user to bypass
    security checks to the keyring. This compromises the
    validity of the keyring for those who rely on it.

  - net/netfilter/xt_osf.c in the Linux kernel through
    4.14.4 does not require the CAP_NET_ADMIN capability
    for add_callback and remove_callback operations. This
    allows local users to bypass intended access
    restrictions because the xt_osf_fingers data structure
    is shared across all network namespaces.

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://help.virtuozzo.com/customer/portal/articles/2942008");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-17448");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-17449");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-17450");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-17807");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-1130");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-5803");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-48.2-52.0-2.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9fc60951");
  script_set_attribute(attribute:"solution", value:"Update the readykernel patch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:readykernel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    "kernel","vzkernel-3.10.0-693.21.1.vz7.48.2",
    "patch","readykernel-patch-48.2-52.0-2.vl7"
  )
);
readykernel_execute_checks(checks:checks, severity:SECURITY_WARNING, release:"Virtuozzo-7");

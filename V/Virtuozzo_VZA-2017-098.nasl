#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104132);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2016-8399",
    "CVE-2017-12188",
    "CVE-2017-12190"
  );

  script_name(english:"Virtuozzo 7 : readykernel-patch (VZA-2017-098)");
  script_summary(english:"Checks the readykernel output for the updated patch.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the vzkernel package and the
readykernel-patch installed, the Virtuozzo installation on the remote
host is affected by the following vulnerabilities :

  - Linux kernel built with the KVM virtualisation support
    (CONFIG_KVM), with nested virtualisation (nVMX) feature
    enabled (nested=1), is vulnerable to a stack buffer
    overflow issue. It could occur while traversing guest
    pagetable entries to resolve guest virtual address. A
    guest system could use this flaw to crash the host
    kernel resulting in DoS, or potentially execute
    arbitrary code on the host.

  - A flaw was found in the Linux networking subsystem
    where a local attacker with CAP_NET_ADMIN capabilities
    could cause an out-of-bounds memory access by creating
    a smaller-than-expected ICMP header and sending to its
    destination via sendto().

  - It was found that in the Linux kernel through
    v4.14-rc5, bio_map_user_iov() and bio_unmap_user() in
    'block/bio.c' do unbalanced pages refcounting if IO
    vector has small consecutive buffers belonging to the
    same page. bio_add_pc_page() merges them into one, but
    the page reference is never dropped, causing a memory
    leak and possible system lockup due to out-of-memory
    condition.

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://help.virtuozzo.com/customer/portal/articles/2892758");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-30.10-35.2-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2636ca46");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-30.15-35.2-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce2ff292");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-33.22-35.2-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ffa1df3");
  script_set_attribute(attribute:"solution", value:"Update the readykernel patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/25");

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
    "patch","readykernel-patch-30.10-35.2-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-514.16.1.vz7.30.15",
    "patch","readykernel-patch-30.15-35.2-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-514.26.1.vz7.33.22",
    "patch","readykernel-patch-33.22-35.2-1.vl7"
  )
);
readykernel_execute_checks(checks:checks, severity:SECURITY_HOLE, release:"Virtuozzo-7");

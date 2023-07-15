#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133461);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2018-20856",
    "CVE-2018-7191"
  );

  script_name(english:"Virtuozzo 7 : readykernel-patch (VZA-2019-081)");
  script_summary(english:"Checks the readykernel output for the updated patch.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the vzkernel package and the
readykernel-patch installed, the Virtuozzo installation on the remote
host is affected by the following vulnerabilities :

  - [3.10.0-693.21.1.vz7.46.7 to 3.10.0-957.12.2.vz7.96.21]
    Use-after-free in __blk_drain_queue() function. It was
    found that a use-after-free condition could be
    triggered in the block device subsystem while the
    outstanding command queue was drained. A patient local
    attacker can use this flaw to crash the system or,
    potentially, to escalate their privileges.

  - [3.10.0-693.21.1.vz7.46.7 to 3.10.0-957.12.2.vz7.96.21]
    tun: potential kernel crash when TUNSETIFF ioctl
    operation is used for a device with an invalid name.

  - [3.10.0-693.21.1.vz7.46.7 to 3.10.0-957.12.2.vz7.96.21]
    Certain operations with iptables in a container may
    crash the kernel.

  - [3.10.0-693.21.1.vz7.46.7 to 3.10.0-957.12.2.vz7.96.21]
    A container that tries to mount NFS shares may cause
    the whole system to hang in certain conditions.

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://virtuozzosupport.force.com/s/article/VZA-2019-081");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1716328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1738705");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-46.7-89.2-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c15051e");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-48.2-89.2-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fddf855e");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-63.3-89.2-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d7ce08c9");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-64.7-89.2-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c250910");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-73.24-89.2-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72420f9b");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-73.29-89.2-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9693c7fe");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-85.17-89.2-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df030fea");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-86.2-89.2-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4271804e");
  # https://readykernel.com/patch/Virtuozzo-7/readykernel-patch-96.21-89.2-1.vl7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b0eb04cb");
  script_set_attribute(attribute:"solution", value:"Update the readykernel patch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20856");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:readykernel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    "kernel","vzkernel-3.10.0-693.21.1.vz7.46.7",
    "patch","readykernel-patch-46.7-89.2-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-693.21.1.vz7.48.2",
    "patch","readykernel-patch-48.2-89.2-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-862.11.6.vz7.64.7",
    "patch","readykernel-patch-63.3-89.2-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-862.20.2.vz7.73.24",
    "patch","readykernel-patch-64.7-89.2-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-862.20.2.vz7.73.29",
    "patch","readykernel-patch-73.24-89.2-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-862.9.1.vz7.63.3",
    "patch","readykernel-patch-73.29-89.2-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-957.10.1.vz7.85.17",
    "patch","readykernel-patch-85.17-89.2-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-957.12.2.vz7.86.2",
    "patch","readykernel-patch-86.2-89.2-1.vl7"
  ),
  make_array(
    "kernel","vzkernel-3.10.0-957.12.2.vz7.96.21",
    "patch","readykernel-patch-96.21-89.2-1.vl7"
  )
);
readykernel_execute_checks(checks:checks, severity:SECURITY_WARNING, release:"Virtuozzo-7");

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:3220 and 
# Oracle Linux Security Advisory ELSA-2020-3220 respectively.
#
# @DEPRECATED@
#
# Disabled on 2020/10/12. Deprecated because security advisory was retracted
# as being non-security related.

include("compat.inc");

if (description)
{
  script_id(139219);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/12");

  script_cve_id("CVE-2019-19527", "CVE-2020-10757", "CVE-2020-12653", "CVE-2020-12654");
  script_xref(name:"RHSA", value:"2020:3220");

  script_name(english:"Oracle Linux 7 : kernel (ELSA-2020-3220) (deprecated)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"From Red Hat Security Advisory 2020:3220 :

The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:3220 advisory.

  - kernel: use-after-free caused by a malicious USB device
    in the drivers/hid/usbhid/hiddev.c driver
    (CVE-2019-19527)

  - kernel: kernel: DAX hugepages not considered during
    mremap (CVE-2020-10757)

  - kernel: buffer overflow in mwifiex_cmd_append_vsie_tlv
    function in drivers/net/wireless/marvell/mwifiex/scan.c
    (CVE-2020-12653)

  - kernel: heap-based buffer overflow in
    mwifiex_ret_wmm_get_status function in
    drivers/net/wireless/marvell/mwifiex/wmm.c
    (CVE-2020-12654)

As of 2020/10/12 this advisory has been retracted because it
apparently does not fix any security problems relevant to already
running systems."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2020-July/010184.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2020-October/010334.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"n/a."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19527");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}

exit(0, "As of 2020/10/12 this advisory has been retracted because it apparently does not fix any security problems relevant to already running systems.");

#if (rpm_check(release:"EL7", cpu:"x86_64", reference:"bpftool-3.10.0-1127.18.2.el7")) flag++;
#if (rpm_exists(release:"EL7", rpm:"kernel-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-3.10.0-1127.18.2.el7")) flag++;
#if (rpm_exists(release:"EL7", rpm:"kernel-abi-whitelists-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-1127.18.2.el7")) flag++;
#if (rpm_exists(release:"EL7", rpm:"kernel-debug-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-1127.18.2.el7")) flag++;
#if (rpm_exists(release:"EL7", rpm:"kernel-debug-devel-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-1127.18.2.el7")) flag++;
#if (rpm_exists(release:"EL7", rpm:"kernel-devel-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-1127.18.2.el7")) flag++;
#if (rpm_exists(release:"EL7", rpm:"kernel-doc-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-doc-3.10.0-1127.18.2.el7")) flag++;
#if (rpm_exists(release:"EL7", rpm:"kernel-headers-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-1127.18.2.el7")) flag++;
#if (rpm_exists(release:"EL7", rpm:"kernel-tools-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-1127.18.2.el7")) flag++;
#if (rpm_exists(release:"EL7", rpm:"kernel-tools-libs-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-1127.18.2.el7")) flag++;
#if (rpm_exists(release:"EL7", rpm:"kernel-tools-libs-devel-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-1127.18.2.el7")) flag++;
#if (rpm_check(release:"EL7", cpu:"x86_64", reference:"perf-3.10.0-1127.18.2.el7")) flag++;
#if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-perf-3.10.0-1127.18.2.el7")) flag++;

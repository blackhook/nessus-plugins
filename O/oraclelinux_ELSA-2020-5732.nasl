#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2020/06/22. Deprecated because security advisory was retracted
# as being non-security related.

include("compat.inc");

if (description)
{
  script_id(137697);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/23");

  script_cve_id("CVE-2020-0543");

  script_name(english:"Oracle Linux 7 : Unbreakable Enterprise kernel (ELSA-2020-5732) (deprecated)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Description of changes:

[4.14.35-1902.303.5.3.el7uek] - rds: Deregister all FRWR mr with free_mr 
(Hans Westgaard Ry) [Orabug: 31476202]
- Revert 'rds: Do not cancel RDMAs that have been posted to the HCA' 
(Gerd Rausch) [Orabug: 31475329]
- Revert 'rds: Introduce rds_conn_to_path helper' (Gerd Rausch) [Orabug: 
31475329]
- Revert 'rds: Three cancel fixes' (Gerd Rausch) [Orabug: 31475318]

[4.14.35-1902.303.5.2.el7uek] - rds: Three cancel fixes (H&aring kon Bugge) 
[Orabug: 31463014]

[4.14.35-1902.303.5.1.el7uek] - x86/speculation: Add SRBDS vulnerability 
and mitigation documentation (Mark Gross) [Orabug: 31446720] 
{CVE-2020-0543} - x86/speculation: Add Special Register Buffer Data 
Sampling (SRBDS) mitigation (Mark Gross) [Orabug: 31446720] 
{CVE-2020-0543} - x86/cpu: Add 'table' argument to cpu_matches() (Mark 
Gross) [Orabug: 31446720] {CVE-2020-0543}
- x86/cpu: Add a steppings field to struct x86_cpu_id (Mark Gross) 
[Orabug: 31446720] {CVE-2020-0543}

[4.14.35-1902.303.5.el7uek] - net/mlx5: Decrease default mr cache size 
(Artemy Kovalyov) [Orabug: 31446379]

As of 2020/06/22 this advisory has been retracted because it
apparently does not fix any security problems relevant to already
running systems."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2020-June/010063.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2020-June/010066.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"n/a"
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}

exit(0, "As of 2020/06/22 this advisory has been retracted because it apparently does not fix any security problems relevant to already running systems.");

#if (rpm_exists(release:"EL7", rpm:"kernel-uek-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-4.14.35-1902.303.5.3.el7uek")) flag++;
#if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-4.14.35-1902.303.5.3.el7uek")) flag++;
#if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-devel-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-devel-4.14.35-1902.303.5.3.el7uek")) flag++;
#if (rpm_exists(release:"EL7", rpm:"kernel-uek-devel-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-devel-4.14.35-1902.303.5.3.el7uek")) flag++;
#if (rpm_exists(release:"EL7", rpm:"kernel-uek-doc-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-doc-4.14.35-1902.303.5.3.el7uek")) flag++;
#if (rpm_exists(release:"EL7", rpm:"kernel-uek-tools-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-tools-4.14.35-1902.303.5.3.el7uek")) flag++;

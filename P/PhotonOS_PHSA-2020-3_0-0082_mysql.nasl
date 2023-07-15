#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2020-3.0-0082. The text
# itself is copyright (C) VMware, Inc.

include('compat.inc');

if (description)
{
  script_id(135872);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2019-2791",
    "CVE-2019-2911",
    "CVE-2019-2914",
    "CVE-2019-2920",
    "CVE-2019-2938",
    "CVE-2019-2946",
    "CVE-2019-2957",
    "CVE-2019-2960",
    "CVE-2019-2963",
    "CVE-2019-2966",
    "CVE-2019-2967",
    "CVE-2019-2968",
    "CVE-2019-2974",
    "CVE-2019-2982",
    "CVE-2019-2991",
    "CVE-2019-2993",
    "CVE-2019-2997",
    "CVE-2019-2998",
    "CVE-2019-3004",
    "CVE-2019-3009",
    "CVE-2019-3011",
    "CVE-2019-3018",
    "CVE-2020-2570",
    "CVE-2020-2572",
    "CVE-2020-2573",
    "CVE-2020-2574",
    "CVE-2020-2577",
    "CVE-2020-2579",
    "CVE-2020-2580",
    "CVE-2020-2584",
    "CVE-2020-2588",
    "CVE-2020-2589",
    "CVE-2020-2627",
    "CVE-2020-2660",
    "CVE-2020-2679",
    "CVE-2020-2686",
    "CVE-2020-2694",
    "CVE-2020-2752",
    "CVE-2020-2759",
    "CVE-2020-2760",
    "CVE-2020-2761",
    "CVE-2020-2762",
    "CVE-2020-2763",
    "CVE-2020-2765",
    "CVE-2020-2768",
    "CVE-2020-2770",
    "CVE-2020-2774",
    "CVE-2020-2779",
    "CVE-2020-2780",
    "CVE-2020-2804",
    "CVE-2020-2812",
    "CVE-2020-2814",
    "CVE-2020-2853",
    "CVE-2020-2892",
    "CVE-2020-2893",
    "CVE-2020-2895",
    "CVE-2020-2896",
    "CVE-2020-2897",
    "CVE-2020-2898",
    "CVE-2020-2901",
    "CVE-2020-2903",
    "CVE-2020-2904",
    "CVE-2020-2921",
    "CVE-2020-2922",
    "CVE-2020-2923",
    "CVE-2020-2924",
    "CVE-2020-2925",
    "CVE-2020-2926",
    "CVE-2020-2928",
    "CVE-2020-2930"
  );
  script_bugtraq_id(109247);
  script_xref(name:"IAVA", value:"2020-A-0143");

  script_name(english:"Photon OS 3.0: Mysql PHSA-2020-3.0-0082");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the mysql package has been released.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Updates-3.0-82.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2760");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-2768");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:3.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"PhotonOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/PhotonOS/release", "Host/PhotonOS/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/PhotonOS/release");
if (isnull(release) || release !~ "^VMware Photon") audit(AUDIT_OS_NOT, "PhotonOS");
if (release !~ "^VMware Photon (?:Linux|OS) 3\.0(\D|$)") audit(AUDIT_OS_NOT, "PhotonOS 3.0");

if (!get_kb_item("Host/PhotonOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "PhotonOS", cpu);

flag = 0;

if (rpm_check(release:"PhotonOS-3.0", cpu:"x86_64", reference:"mysql-8.0.19-1.ph3")) flag++;
if (rpm_check(release:"PhotonOS-3.0", cpu:"x86_64", reference:"mysql-debuginfo-8.0.19-1.ph3")) flag++;
if (rpm_check(release:"PhotonOS-3.0", cpu:"x86_64", reference:"mysql-devel-8.0.19-1.ph3")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql");
}

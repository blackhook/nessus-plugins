#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2/7/2019
#

# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2017-0034. The text
# itself is copyright (C) VMware, Inc.

include("compat.inc");

if (description)
{
  script_id(111883);
  script_version("1.2");
  script_cvs_date("Date: 2019/02/07 18:59:50");

  script_cve_id(
    "CVE-2017-12893",
    "CVE-2017-12894",
    "CVE-2017-12895",
    "CVE-2017-12896",
    "CVE-2017-12897",
    "CVE-2017-12898",
    "CVE-2017-12899",
    "CVE-2017-12900",
    "CVE-2017-12901",
    "CVE-2017-12902",
    "CVE-2017-12985",
    "CVE-2017-12986",
    "CVE-2017-12987",
    "CVE-2017-12988",
    "CVE-2017-12989",
    "CVE-2017-12990",
    "CVE-2017-12991",
    "CVE-2017-12992",
    "CVE-2017-12993",
    "CVE-2017-12994",
    "CVE-2017-12995",
    "CVE-2017-12996",
    "CVE-2017-12997",
    "CVE-2017-12998",
    "CVE-2017-12999",
    "CVE-2017-13000",
    "CVE-2017-13001",
    "CVE-2017-13002",
    "CVE-2017-13003",
    "CVE-2017-13004",
    "CVE-2017-13005",
    "CVE-2017-13006",
    "CVE-2017-13007",
    "CVE-2017-13008",
    "CVE-2017-13009",
    "CVE-2017-13010",
    "CVE-2017-13011",
    "CVE-2017-13012",
    "CVE-2017-13013",
    "CVE-2017-13014",
    "CVE-2017-13015",
    "CVE-2017-13016",
    "CVE-2017-13017",
    "CVE-2017-13018",
    "CVE-2017-13019",
    "CVE-2017-13020",
    "CVE-2017-13021",
    "CVE-2017-13022",
    "CVE-2017-13023",
    "CVE-2017-13024",
    "CVE-2017-13025",
    "CVE-2017-13026",
    "CVE-2017-13027",
    "CVE-2017-13028",
    "CVE-2017-13029",
    "CVE-2017-13030",
    "CVE-2017-13031",
    "CVE-2017-13032",
    "CVE-2017-13033",
    "CVE-2017-13034",
    "CVE-2017-13035",
    "CVE-2017-13036",
    "CVE-2017-13037",
    "CVE-2017-13038",
    "CVE-2017-13039",
    "CVE-2017-13040",
    "CVE-2017-13041",
    "CVE-2017-13042",
    "CVE-2017-13043",
    "CVE-2017-13044",
    "CVE-2017-13045",
    "CVE-2017-13046",
    "CVE-2017-13047",
    "CVE-2017-13048",
    "CVE-2017-13049",
    "CVE-2017-13050",
    "CVE-2017-13051",
    "CVE-2017-13052",
    "CVE-2017-13053",
    "CVE-2017-13054",
    "CVE-2017-13055",
    "CVE-2017-13687",
    "CVE-2017-13688",
    "CVE-2017-13689",
    "CVE-2017-13690",
    "CVE-2017-13725",
    "CVE-2017-14064"
  );

  script_name(english:"Photon OS 1.0: Ruby / Tcpdump PHSA-2017-0034 (deprecated)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"An update of [tcpdump,ruby] packages for PhotonOS has been released.");
  # https://github.com/vmware/photon/wiki/Security-Updates-70
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5900e66");
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12893");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:tcpdump");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:1.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"PhotonOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/PhotonOS/release", "Host/PhotonOS/rpm-list");

  exit(0);
}

exit(0, "This plugin has been deprecated.");

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/PhotonOS/release");
if (isnull(release) || release !~ "^VMware Photon") audit(AUDIT_OS_NOT, "PhotonOS");
if (release !~ "^VMware Photon (?:Linux|OS) 1\.0(\D|$)") audit(AUDIT_OS_NOT, "PhotonOS 1.0");

if (!get_kb_item("Host/PhotonOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "PhotonOS", cpu);

flag = 0;

pkgs = [
  "ruby-2.4.0-6.ph1",
  "ruby-debuginfo-2.4.0-6.ph1",
  "tcpdump-4.9.2-1.ph1",
  "tcpdump-debuginfo-4.9.2-1.ph1"
];

foreach (pkg in pkgs)
  if (rpm_check(release:"PhotonOS-1.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby / tcpdump");
}

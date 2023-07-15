#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-32a4a94c72.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102099);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-11671");
  script_xref(name:"FEDORA", value:"2017-32a4a94c72");

  script_name(english:"Fedora 25 : gcc / gcc-python-plugin / libtool (2017-32a4a94c72)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fixes CVE-2017-11671. Fixed bugs (http://gcc.gnu.org/PRNNNNN): 31468,
43434, 45053, 49244, 50345, 53915, 56469, 60818, 60992, 61636, 61729,
62045, 64238, 65542, 65705, 65972, 66295, 66669, 67353, 67440, 68163,
68491, 68972, 69264, 69699, 69804, 69823, 69953, 70601, 70844, 70878,
71294, 71310, 71444, 71458, 71510, 71778, 71838, 72775, 73650, 75964,
76731, 77333, 77563, 77728, 77850, 78002, 78049, 78236, 78282, 78331,
78339, 78474, 78532, 78543, 78644, 78783, 78992, 79027, 79050, 79141,
79155, 79255, 79256, 79261, 79264, 79396, 79434, 79439, 79453, 79461,
79494, 79508, 79511, 79512, 79514, 79519, 79536, 79537, 79544, 79545,
79548, 79552, 79558, 79559, 79562, 79566, 79568, 79570, 79572, 79574,
79576, 79577, 79579, 79580, 79587, 79607, 79631, 79639, 79640, 79641,
79664, 79666, 79676, 79681, 79687, 79729, 79732, 79733, 79749, 79752,
79753, 79756, 79760, 79761, 79769, 79770, 79789, 79796, 79803, 79807,
79831, 79849, 79850, 79883, 79892, 79894, 79896, 79900, 79901, 79903,
79906, 79931, 79932, 79940, 79944, 79945, 79947, 79951, 79962, 79971,
79977, 79980, 79984, 80004, 80019, 80025, 80034, 80037, 80041, 80043,
80067, 80075, 80081, 80082, 80090, 80091, 80092, 80094, 80097, 80101,
80103, 80104, 80112, 80113, 80117, 80122, 80123, 80129, 80137, 80141,
80150, 80166, 80167, 80168, 80170, 80171, 80176, 80179, 80180, 80181,
80205, 80212, 80218, 80222, 80224, 80241, 80244, 80246, 80262, 80267,
80275, 80281, 80286, 80294, 80297, 80298, 80315, 80316, 80321, 80334,
80341, 80348, 80349, 80350, 80361, 80362, 80363, 80376, 80382, 80385,
80392, 80394, 80413, 80426, 80429, 80448, 80453, 80462, 80474, 80492,
80493, 80501, 80504, 80510, 80539, 80569, 80589, 80618, 80663, 80678,
80692, 80718, 80752, 80799, 80809, 80822, 80853, 80902, 80904, 80909,
80918, 80921, 80929, 80966, 80968, 80973, 80984, 81002, 81006, 81011,
81130, 81154, 81162, 81192, 81300, 81305, 81375, 81407, 81471, 81487,
81555, 81556

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://gcc.gnu.org/PRNNNNN"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-32a4a94c72"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gcc, gcc-python-plugin and / or libtool packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gcc-python-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libtool");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^25([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 25", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC25", reference:"gcc-6.4.1-1.fc25")) flag++;
if (rpm_check(release:"FC25", reference:"gcc-python-plugin-0.15-8.2.fc25")) flag++;
if (rpm_check(release:"FC25", reference:"libtool-2.4.6-14.fc25")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gcc / gcc-python-plugin / libtool");
}

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:3343-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(143664);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_name(english:"SUSE SLES12 Security Update : postgresql, postgresql96, postgresql10 / postgresql12 (SUSE-SU-2020:3343-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update changes the internal packaging for postgresql, and so
contains all currently maintained postgresql versions across our SUSE
Linux Enterprise 12 products.

postgresql12 is shipped new in version 12.3 (bsc#1171924).

The server and client packages only on SUSE Linux Enterprise Server 12
SP5, the libraries on SUSE Linux Enterprise Server 12 SP2 LTSS up to
12 SP5.

  + https://www.postgresql.org/about/news/2038/

  + https://www.postgresql.org/docs/12/release-12-3.html

postgresql10 is updated to 10.13 (bsc#1171924).

On SUSE Linux Enterprise Server 12 SP2 LTSS up to 12 SP5.

  + https://www.postgresql.org/about/news/2038/

  + https://www.postgresql.org/docs/10/release-10-13.html

postgresql96 is updated to 9.6.18 (bsc#1171924) :

  + https://www.postgresql.org/about/news/2038/

  + https://www.postgresql.org/docs/9.6/release-9-6-18.html

    On SUSE Linux Enterprise Server 12-SP2 and 12-SP3 LTSS
    only.

postgresql 9.4 is updated to 9.4.26 :

  + https://www.postgresql.org/about/news/2011/

  + https://www.postgresql.org/docs/9.4/release-9-4-26.html

  + https://www.postgresql.org/about/news/1994/

  + https://www.postgresql.org/docs/9.4/release-9-4-25.html

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1171924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/about/news/1994/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/about/news/2011/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/about/news/2038/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/10/release-10-13.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/12/release-12-3.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/9.4/release-9-4-25.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/9.4/release-9-4-26.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.postgresql.org/docs/9.6/release-9-6-18.html"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20203343-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?60e96989"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 9 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-9-2020-3343=1

SUSE OpenStack Cloud Crowbar 8 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-8-2020-3343=1

SUSE OpenStack Cloud 9 :

zypper in -t patch SUSE-OpenStack-Cloud-9-2020-3343=1

SUSE OpenStack Cloud 8 :

zypper in -t patch SUSE-OpenStack-Cloud-8-2020-3343=1

SUSE OpenStack Cloud 7 :

zypper in -t patch SUSE-OpenStack-Cloud-7-2020-3343=1

SUSE Linux Enterprise Software Development Kit 12-SP5 :

zypper in -t patch SUSE-SLE-SDK-12-SP5-2020-3343=1

SUSE Linux Enterprise Server for SAP 12-SP4 :

zypper in -t patch SUSE-SLE-SAP-12-SP4-2020-3343=1

SUSE Linux Enterprise Server for SAP 12-SP3 :

zypper in -t patch SUSE-SLE-SAP-12-SP3-2020-3343=1

SUSE Linux Enterprise Server for SAP 12-SP2 :

zypper in -t patch SUSE-SLE-SAP-12-SP2-2020-3343=1

SUSE Linux Enterprise Server 12-SP5 :

zypper in -t patch SUSE-SLE-SERVER-12-SP5-2020-3343=1

SUSE Linux Enterprise Server 12-SP4-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP4-LTSS-2020-3343=1

SUSE Linux Enterprise Server 12-SP3-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-2020-3343=1

SUSE Linux Enterprise Server 12-SP3-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-BCL-2020-3343=1

SUSE Linux Enterprise Server 12-SP2-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-2020-3343=1

SUSE Linux Enterprise Server 12-SP2-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-BCL-2020-3343=1

SUSE Enterprise Storage 5 :

zypper in -t patch SUSE-Storage-5-2020-3343=1

HPE Helion Openstack 8 :

zypper in -t patch HPE-Helion-OpenStack-8-2020-3343=1"
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libecpg6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpq5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql10-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql12-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql94");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql94-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql94-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql94-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql94-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql94-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql94-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql94-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql94-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql94-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql94-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql94-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql94-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql96-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4/5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"libecpg6-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libecpg6-debuginfo-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libpq5-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libpq5-32bit-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libpq5-debuginfo-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libpq5-debuginfo-32bit-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"postgresql10-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"postgresql10-contrib-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"postgresql10-contrib-debuginfo-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"postgresql10-debuginfo-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"postgresql10-debugsource-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"postgresql10-plperl-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"postgresql10-plperl-debuginfo-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"postgresql10-plpython-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"postgresql10-plpython-debuginfo-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"postgresql10-pltcl-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"postgresql10-pltcl-debuginfo-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"postgresql10-server-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"postgresql10-server-debuginfo-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libecpg6-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libecpg6-debuginfo-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpq5-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpq5-32bit-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpq5-debuginfo-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpq5-debuginfo-32bit-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql10-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql10-contrib-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql10-contrib-debuginfo-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql10-debuginfo-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql10-debugsource-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql10-plperl-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql10-plperl-debuginfo-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql10-plpython-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql10-plpython-debuginfo-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql10-pltcl-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql10-pltcl-debuginfo-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql10-server-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql10-server-debuginfo-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-contrib-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-contrib-debuginfo-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-debuginfo-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-debugsource-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-plperl-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-plperl-debuginfo-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-plpython-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-plpython-debuginfo-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-pltcl-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-pltcl-debuginfo-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-server-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"postgresql96-server-debuginfo-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libecpg6-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libecpg6-debuginfo-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libpq5-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libpq5-32bit-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libpq5-debuginfo-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libpq5-debuginfo-32bit-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql10-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql10-contrib-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql10-contrib-debuginfo-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql10-debuginfo-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql10-debugsource-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql10-plperl-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql10-plperl-debuginfo-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql10-plpython-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql10-plpython-debuginfo-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql10-pltcl-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql10-pltcl-debuginfo-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql10-server-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql10-server-debuginfo-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql94-9.4.26-24.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql94-contrib-9.4.26-24.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql94-contrib-debuginfo-9.4.26-24.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql94-debuginfo-9.4.26-24.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql94-debugsource-9.4.26-24.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql94-plperl-9.4.26-24.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql94-plperl-debuginfo-9.4.26-24.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql94-plpython-9.4.26-24.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql94-plpython-debuginfo-9.4.26-24.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql94-pltcl-9.4.26-24.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql94-pltcl-debuginfo-9.4.26-24.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql94-server-9.4.26-24.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql94-server-debuginfo-9.4.26-24.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-contrib-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-contrib-debuginfo-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-debuginfo-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-debugsource-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-plperl-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-plperl-debuginfo-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-plpython-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-plpython-debuginfo-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-pltcl-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-pltcl-debuginfo-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-server-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"postgresql96-server-debuginfo-9.6.19-6.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libecpg6-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libecpg6-debuginfo-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libpq5-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libpq5-32bit-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libpq5-debuginfo-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libpq5-debuginfo-32bit-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql10-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql10-contrib-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql10-contrib-debuginfo-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql10-debuginfo-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql10-debugsource-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql10-plperl-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql10-plperl-debuginfo-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql10-plpython-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql10-plpython-debuginfo-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql10-pltcl-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql10-pltcl-debuginfo-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql10-server-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql10-server-debuginfo-10.14-4.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-contrib-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-contrib-debuginfo-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-debuginfo-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-debugsource-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-plperl-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-plperl-debuginfo-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-plpython-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-plpython-debuginfo-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-pltcl-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-pltcl-debuginfo-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-server-12.4-3.5.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"postgresql12-server-debuginfo-12.4-3.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql96 / postgresql10 / postgresql12");
}

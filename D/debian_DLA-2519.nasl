#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2519-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(144814);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id("CVE-2018-16877", "CVE-2018-16878", "CVE-2020-25654");

  script_name(english:"Debian DLA-2519-1 : pacemaker security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several security vulnerabilities were addressed in pacemaker, a
cluster resource manager.

CVE-2018-16877

A flaw was found in the way pacemaker's client-server authentication
was implemented. A local attacker could use this flaw, and combine it
with other IPC weaknesses, to achieve local privilege escalation.

CVE-2018-16878

An insufficient verification inflicted preference of uncontrolled
processes can lead to denial of service.

CVE-2020-25654

An ACL bypass flaw was found in pacemaker. An attacker having a local
account on the cluster and in the haclient group could use IPC
communication with various daemons directly to perform certain tasks
that they would be prevented by ACLs from doing if they went through
the configuration.

For Debian 9 stretch, these problems have been fixed in version
1.1.24-0+deb9u1.

We recommend that you upgrade your pacemaker packages.

For the detailed security status of pacemaker please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/pacemaker

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/01/msg00007.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/pacemaker"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/pacemaker"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25654");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcib4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcrmcluster-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcrmcluster4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcrmcommon-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcrmcommon3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcrmservice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcrmservice3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblrmd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblrmd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpe-rules2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpe-status10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpengine-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpengine10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libstonithd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libstonithd2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtransitioner2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pacemaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pacemaker-cli-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pacemaker-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pacemaker-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pacemaker-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pacemaker-resource-agents");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"9.0", prefix:"libcib-dev", reference:"1.1.24-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcib4", reference:"1.1.24-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcrmcluster-dev", reference:"1.1.24-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcrmcluster4", reference:"1.1.24-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcrmcommon-dev", reference:"1.1.24-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcrmcommon3", reference:"1.1.24-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcrmservice-dev", reference:"1.1.24-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libcrmservice3", reference:"1.1.24-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"liblrmd-dev", reference:"1.1.24-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"liblrmd1", reference:"1.1.24-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpe-rules2", reference:"1.1.24-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpe-status10", reference:"1.1.24-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpengine-dev", reference:"1.1.24-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpengine10", reference:"1.1.24-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libstonithd-dev", reference:"1.1.24-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libstonithd2", reference:"1.1.24-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libtransitioner2", reference:"1.1.24-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"pacemaker", reference:"1.1.24-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"pacemaker-cli-utils", reference:"1.1.24-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"pacemaker-common", reference:"1.1.24-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"pacemaker-doc", reference:"1.1.24-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"pacemaker-remote", reference:"1.1.24-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"pacemaker-resource-agents", reference:"1.1.24-0+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

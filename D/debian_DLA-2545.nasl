#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2545-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(146119);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id("CVE-2020-8020", "CVE-2020-8021");

  script_name(english:"Debian DLA-2545-1 : open-build-service security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"CVE-2020-8020

An improper neutralization of input during web page generation
vulnerability in open-build-service allows remote attackers to store
arbitrary JS code to cause XSS.

CVE-2020-8021

An improper access control vulnerability in open-build-service allows
remote attackers to read files of an OBS package where the
sourceaccess/access is disabled.

For Debian 9 stretch, these problems have been fixed in version
2.7.1-10+deb9u1.

We recommend that you upgrade your open-build-service packages.

For the detailed security status of open-build-service please refer to
its security tracker page at:
https://security-tracker.debian.org/tracker/open-build-service

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/02/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/open-build-service"
  );
  # https://security-tracker.debian.org/tracker/source-package/open-build-service
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8317018"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8021");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:obs-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:obs-productconverter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:obs-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:obs-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:obs-worker");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/04");
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
if (deb_check(release:"9.0", prefix:"obs-api", reference:"2.7.1-10+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"obs-productconverter", reference:"2.7.1-10+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"obs-server", reference:"2.7.1-10+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"obs-utils", reference:"2.7.1-10+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"obs-worker", reference:"2.7.1-10+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

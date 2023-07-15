#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1900-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128306);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2019-10092");

  script_name(english:"Debian DLA-1900-2 : apache2 regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The update of apache2 released as DLA-1900-1 contained an incomplete
fix for CVE-2019-10092, a limited cross-site scripting issue affecting
the mod_proxy error page. The old patch rather introduced a new CSRF
protection which also caused a regression, an inability to dynamically
change the status of members in the balancer via the balancer-manager.
This update reverts the change and provides the correct upstream patch
to address CVE-2019-10092.

For Debian 8 'Jessie', this problem has been fixed in version
2.4.10-10+deb8u16.

We recommend that you upgrade your apache2 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/09/msg00034.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/apache2"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-mpm-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-mpm-itk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-mpm-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-mpm-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-suexec-custom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-suexec-pristine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2.2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2.2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-macro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-proxy-html");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"apache2", reference:"2.4.10-10+deb8u16")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-bin", reference:"2.4.10-10+deb8u16")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-data", reference:"2.4.10-10+deb8u16")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-dbg", reference:"2.4.10-10+deb8u16")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-dev", reference:"2.4.10-10+deb8u16")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-doc", reference:"2.4.10-10+deb8u16")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-mpm-event", reference:"2.4.10-10+deb8u16")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-mpm-itk", reference:"2.4.10-10+deb8u16")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-mpm-prefork", reference:"2.4.10-10+deb8u16")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-mpm-worker", reference:"2.4.10-10+deb8u16")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-suexec", reference:"2.4.10-10+deb8u16")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-suexec-custom", reference:"2.4.10-10+deb8u16")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-suexec-pristine", reference:"2.4.10-10+deb8u16")) flag++;
if (deb_check(release:"8.0", prefix:"apache2-utils", reference:"2.4.10-10+deb8u16")) flag++;
if (deb_check(release:"8.0", prefix:"apache2.2-bin", reference:"2.4.10-10+deb8u16")) flag++;
if (deb_check(release:"8.0", prefix:"apache2.2-common", reference:"2.4.10-10+deb8u16")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-mod-macro", reference:"2.4.10-10+deb8u16")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-mod-proxy-html", reference:"2.4.10-10+deb8u16")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

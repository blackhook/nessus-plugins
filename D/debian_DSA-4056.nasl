#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4056. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105088);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-16239");
  script_xref(name:"DSA", value:"4056");

  script_name(english:"Debian DSA-4056-1 : nova - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"George Shuklin from servers.com discovered that Nova, a cloud
computing fabric controller, did not correctly enforce its image- or
hosts-filters. This allowed an authenticated user to bypass those
filters by simply rebuilding an instance."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=882009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/nova"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/nova"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-4056"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the nova packages.

For the stable distribution (stretch), this problem has been fixed in
version 2:14.0.0-4+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nova");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"nova-api", reference:"2:14.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"nova-cells", reference:"2:14.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"nova-cert", reference:"2:14.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"nova-common", reference:"2:14.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"nova-compute", reference:"2:14.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"nova-compute-ironic", reference:"2:14.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"nova-compute-kvm", reference:"2:14.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"nova-compute-lxc", reference:"2:14.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"nova-compute-qemu", reference:"2:14.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"nova-conductor", reference:"2:14.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"nova-console", reference:"2:14.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"nova-consoleauth", reference:"2:14.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"nova-consoleproxy", reference:"2:14.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"nova-doc", reference:"2:14.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"nova-network", reference:"2:14.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"nova-placement-api", reference:"2:14.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"nova-scheduler", reference:"2:14.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"nova-volume", reference:"2:14.0.0-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python-nova", reference:"2:14.0.0-4+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

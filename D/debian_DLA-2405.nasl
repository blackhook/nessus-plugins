#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2405-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(141389);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-13956");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Debian DLA-2405-1 : httpcomponents-client security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Oleg Kalnichevski discovered that httpcomponents-client, a Java
library for building HTTP-aware applications, can misinterpret a
malformed authority component in request URIs passed to the library as
java.net.URI object and pick the wrong target host for request
execution.

For Debian 9 stretch, this problem has been fixed in version
4.5.2-2+deb9u1.

We recommend that you upgrade your httpcomponents-client packages.

For the detailed security status of httpcomponents-client please refer
to its security tracker page at:
https://security-tracker.debian.org/tracker/httpcomponents-client

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/10/msg00017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/httpcomponents-client"
  );
  # https://security-tracker.debian.org/tracker/source-package/httpcomponents-client
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8b769c2"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhttpclient-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhttpmime-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"libhttpclient-java", reference:"4.5.2-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libhttpmime-java", reference:"4.5.2-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

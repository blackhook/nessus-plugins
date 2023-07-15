#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4757. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(140104);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2020-11984", "CVE-2020-11993", "CVE-2020-1927", "CVE-2020-1934", "CVE-2020-9490");
  script_xref(name:"DSA", value:"4757");
  script_xref(name:"IAVA", value:"2020-A-0376-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Debian DSA-4757-1 : apache2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been found in the Apache HTTPD server.

  - CVE-2020-1927
    Fabrice Perez reported that certain mod_rewrite
    configurations are prone to an open redirect.

  - CVE-2020-1934
    Chamal De Silva discovered that the mod_proxy_ftp module
    uses uninitialized memory when proxying to a malicious
    FTP backend.

  - CVE-2020-9490
    Felix Wilhelm discovered that a specially crafted value
    for the 'Cache-Digest' header in a HTTP/2 request could
    cause a crash when the server actually tries to HTTP/2
    PUSH a resource afterwards.

  - CVE-2020-11984
    Felix Wilhelm reported a buffer overflow flaw in the
    mod_proxy_uwsgi module which could result in information
    disclosure or potentially remote code execution.

  - CVE-2020-11993
    Felix Wilhelm reported that when trace/debug was enabled
    for the HTTP/2 module certain traffic edge patterns can
    cause logging statements on the wrong connection,
    causing concurrent use of memory pools."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-1927"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-1934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-9490"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-11984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-11993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/apache2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/apache2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4757"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the apache2 packages.

For the stable distribution (buster), these problems have been fixed
in version 2.4.38-3+deb10u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (deb_check(release:"10.0", prefix:"apache2", reference:"2.4.38-3+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"apache2-bin", reference:"2.4.38-3+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"apache2-data", reference:"2.4.38-3+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"apache2-dev", reference:"2.4.38-3+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"apache2-doc", reference:"2.4.38-3+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"apache2-ssl-dev", reference:"2.4.38-3+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"apache2-suexec-custom", reference:"2.4.38-3+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"apache2-suexec-pristine", reference:"2.4.38-3+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"apache2-utils", reference:"2.4.38-3+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"libapache2-mod-md", reference:"2.4.38-3+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"libapache2-mod-proxy-uwsgi", reference:"2.4.38-3+deb10u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4509. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128182);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2019-10081", "CVE-2019-10082", "CVE-2019-10092", "CVE-2019-10097", "CVE-2019-10098", "CVE-2019-9517");
  script_xref(name:"DSA", value:"4509");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"Debian DSA-4509-1 : apache2 - security update (Internal Data Buffering)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been found in the Apache HTTPD server.

  - CVE-2019-9517
    Jonathan Looney reported that a malicious client could
    perform a denial of service attack (exhausting h2
    workers) by flooding a connection with requests and
    basically never reading responses on the TCP connection.

  - CVE-2019-10081
    Craig Young reported that HTTP/2 PUSHes could lead to an
    overwrite of memory in the pushing request's pool,
    leading to crashes.

  - CVE-2019-10082
    Craig Young reported that the HTTP/2 session handling
    could be made to read memory after being freed, during
    connection shutdown.

  - CVE-2019-10092
    Matei 'Mal' Badanoiu reported a limited cross-site
    scripting vulnerability in the mod_proxy error page.

  - CVE-2019-10097
    Daniel McCarney reported that when mod_remoteip was
    configured to use a trusted intermediary proxy server
    using the 'PROXY' protocol, a specially crafted PROXY
    header could trigger a stack buffer overflow or NULL
    pointer deference. This vulnerability could only be
    triggered by a trusted proxy and not by untrusted HTTP
    clients. The issue does not affect the stretch release.

  - CVE-2019-10098
    Yukitsugu Sasaki reported a potential open redirect
    vulnerability in the mod_rewrite module."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-9517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-10081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-10082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-10092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-10097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-10098"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/apache2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/apache2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/apache2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4509"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the apache2 packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 2.4.25-3+deb9u8.

For the stable distribution (buster), these problems have been fixed
in version 2.4.38-3+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10082");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/27");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"apache2", reference:"2.4.38-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"apache2-bin", reference:"2.4.38-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"apache2-data", reference:"2.4.38-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"apache2-dev", reference:"2.4.38-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"apache2-doc", reference:"2.4.38-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"apache2-ssl-dev", reference:"2.4.38-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"apache2-suexec-custom", reference:"2.4.38-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"apache2-suexec-pristine", reference:"2.4.38-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"apache2-utils", reference:"2.4.38-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libapache2-mod-md", reference:"2.4.38-3+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libapache2-mod-proxy-uwsgi", reference:"2.4.38-3+deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"apache2", reference:"2.4.25-3+deb9u8")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-bin", reference:"2.4.25-3+deb9u8")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-data", reference:"2.4.25-3+deb9u8")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-dbg", reference:"2.4.25-3+deb9u8")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-dev", reference:"2.4.25-3+deb9u8")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-doc", reference:"2.4.25-3+deb9u8")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-ssl-dev", reference:"2.4.25-3+deb9u8")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-suexec-custom", reference:"2.4.25-3+deb9u8")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-suexec-pristine", reference:"2.4.25-3+deb9u8")) flag++;
if (deb_check(release:"9.0", prefix:"apache2-utils", reference:"2.4.25-3+deb9u8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

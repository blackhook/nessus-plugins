#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5722-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167542);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-41741", "CVE-2022-41742");
  script_xref(name:"USN", value:"5722-1");
  script_xref(name:"IAVA", value:"2022-A-0440");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 : nginx vulnerabilities (USN-5722-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-5722-1 advisory.

  - NGINX Open Source before versions 1.23.2 and 1.22.1, NGINX Open Source Subscription before versions R2 P1
    and R1 P1, and NGINX Plus before versions R27 P1 and R26 P1 have a vulnerability in the module
    ngx_http_mp4_module that might allow a local attacker to corrupt NGINX worker memory, resulting in its
    termination or potential other impact using a specially crafted audio or video file. The issue affects
    only NGINX products that are built with the ngx_http_mp4_module, when the mp4 directive is used in the
    configuration file. Further, the attack is possible only if an attacker can trigger processing of a
    specially crafted audio or video file with the module ngx_http_mp4_module. (CVE-2022-41741)

  - NGINX Open Source before versions 1.23.2 and 1.22.1, NGINX Open Source Subscription before versions R2 P1
    and R1 P1, and NGINX Plus before versions R27 P1 and R26 P1 have a vulnerability in the module
    ngx_http_mp4_module that might allow a local attacker to cause a worker process crash, or might result in
    worker process memory disclosure by using a specially crafted audio or video file. The issue affects only
    NGINX products that are built with the module ngx_http_mp4_module, when the mp4 directive is used in the
    configuration file. Further, the attack is possible only if an attacker can trigger processing of a
    specially crafted audio or video file with the module ngx_http_mp4_module. (CVE-2022-41742)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5722-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41741");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-auth-pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-cache-purge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-dav-ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-echo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-fancyindex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-geoip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-headers-more-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-image-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-ndk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-subs-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-uploadprogress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-upstream-fair");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-http-xslt-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-nchan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-rtmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-stream-geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnginx-mod-stream-geoip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nginx-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nginx-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nginx-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nginx-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nginx-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nginx-light");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nginx-naxsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nginx-naxsi-ui");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '22.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'nginx', 'pkgver': '1.10.3-0ubuntu0.16.04.5+esm5'},
    {'osver': '16.04', 'pkgname': 'nginx-common', 'pkgver': '1.10.3-0ubuntu0.16.04.5+esm5'},
    {'osver': '16.04', 'pkgname': 'nginx-core', 'pkgver': '1.10.3-0ubuntu0.16.04.5+esm5'},
    {'osver': '16.04', 'pkgname': 'nginx-extras', 'pkgver': '1.10.3-0ubuntu0.16.04.5+esm5'},
    {'osver': '16.04', 'pkgname': 'nginx-full', 'pkgver': '1.10.3-0ubuntu0.16.04.5+esm5'},
    {'osver': '16.04', 'pkgname': 'nginx-light', 'pkgver': '1.10.3-0ubuntu0.16.04.5+esm5'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-auth-pam', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-cache-purge', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-dav-ext', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-echo', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-fancyindex', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-geoip', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-headers-more-filter', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-image-filter', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-lua', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-ndk', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-perl', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-subs-filter', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-uploadprogress', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-upstream-fair', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-http-xslt-filter', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-mail', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-nchan', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-rtmp', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'libnginx-mod-stream', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'nginx', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'nginx-common', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'nginx-core', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'nginx-extras', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'nginx-full', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '18.04', 'pkgname': 'nginx-light', 'pkgver': '1.14.0-0ubuntu1.11'},
    {'osver': '20.04', 'pkgname': 'libnginx-mod-http-auth-pam', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'libnginx-mod-http-cache-purge', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'libnginx-mod-http-dav-ext', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'libnginx-mod-http-echo', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'libnginx-mod-http-fancyindex', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'libnginx-mod-http-geoip', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'libnginx-mod-http-geoip2', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'libnginx-mod-http-headers-more-filter', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'libnginx-mod-http-image-filter', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'libnginx-mod-http-lua', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'libnginx-mod-http-ndk', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'libnginx-mod-http-perl', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'libnginx-mod-http-subs-filter', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'libnginx-mod-http-uploadprogress', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'libnginx-mod-http-upstream-fair', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'libnginx-mod-http-xslt-filter', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'libnginx-mod-mail', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'libnginx-mod-nchan', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'libnginx-mod-rtmp', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'libnginx-mod-stream', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'nginx', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'nginx-common', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'nginx-core', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'nginx-extras', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'nginx-full', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'nginx-light', 'pkgver': '1.18.0-0ubuntu1.4'},
    {'osver': '22.04', 'pkgname': 'libnginx-mod-http-auth-pam', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'libnginx-mod-http-cache-purge', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'libnginx-mod-http-dav-ext', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'libnginx-mod-http-echo', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'libnginx-mod-http-fancyindex', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'libnginx-mod-http-geoip', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'libnginx-mod-http-geoip2', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'libnginx-mod-http-headers-more-filter', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'libnginx-mod-http-image-filter', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'libnginx-mod-http-ndk', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'libnginx-mod-http-perl', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'libnginx-mod-http-subs-filter', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'libnginx-mod-http-uploadprogress', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'libnginx-mod-http-upstream-fair', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'libnginx-mod-http-xslt-filter', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'libnginx-mod-mail', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'libnginx-mod-nchan', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'libnginx-mod-rtmp', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'libnginx-mod-stream', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'libnginx-mod-stream-geoip', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'libnginx-mod-stream-geoip2', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'nginx', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'nginx-common', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'nginx-core', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'nginx-extras', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'nginx-full', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.04', 'pkgname': 'nginx-light', 'pkgver': '1.18.0-6ubuntu14.3'},
    {'osver': '22.10', 'pkgname': 'libnginx-mod-http-auth-pam', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libnginx-mod-http-cache-purge', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libnginx-mod-http-dav-ext', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libnginx-mod-http-echo', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libnginx-mod-http-fancyindex', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libnginx-mod-http-geoip', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libnginx-mod-http-geoip2', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libnginx-mod-http-headers-more-filter', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libnginx-mod-http-image-filter', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libnginx-mod-http-ndk', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libnginx-mod-http-perl', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libnginx-mod-http-subs-filter', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libnginx-mod-http-uploadprogress', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libnginx-mod-http-upstream-fair', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libnginx-mod-http-xslt-filter', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libnginx-mod-mail', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libnginx-mod-nchan', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libnginx-mod-rtmp', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libnginx-mod-stream', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libnginx-mod-stream-geoip', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'libnginx-mod-stream-geoip2', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'nginx', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'nginx-common', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'nginx-core', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'nginx-dev', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'nginx-extras', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'nginx-full', 'pkgver': '1.22.0-1ubuntu1.1'},
    {'osver': '22.10', 'pkgname': 'nginx-light', 'pkgver': '1.22.0-1ubuntu1.1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnginx-mod-http-auth-pam / libnginx-mod-http-cache-purge / etc');
}

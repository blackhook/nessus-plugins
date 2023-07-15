##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:1313. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148903);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id(
    "CVE-2017-2662",
    "CVE-2019-18874",
    "CVE-2020-9402",
    "CVE-2020-11612",
    "CVE-2020-14335",
    "CVE-2020-25633"
  );
  script_xref(name:"RHSA", value:"2021:1313");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 7 : Satellite 6.9 Release (Moderate) (RHSA-2021:1313)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:1313 advisory.

  - rubygem-rest-client: session fixation vulnerability Set-Cookie headers present in an HTTP 30x redirection
    responses (CVE-2015-1820)

  - rubygem-rest-client: unsanitized application logging (CVE-2015-3448)

  - foreman: Managing repositories with their id via hammer does not respect the role filters (CVE-2017-2662)

  - rack-protection: Timing attack in authenticity_token.rb (CVE-2018-1000119)

  - rubygem-rack: hijack sessions by using timing attacks targeting the session id (CVE-2019-16782)

  - python-psutil: Double free because of refcount mishandling (CVE-2019-18874)

  - netty: compression/decompression codecs don't enforce limits on buffer allocation sizes (CVE-2020-11612)

  - foreman: world-readable OMAPI secret through the ISC DHCP server (CVE-2020-14335)

  - rubygem-activeview: Cross-site scripting in translation helpers (CVE-2020-15169)

  - resteasy-client: potential sensitive information leakage in JAX-RS RESTEasy Client's
    WebApplicationException handling (CVE-2020-25633)

  - rubygem-activestorage: circumvention of file size limits in ActiveStorage (CVE-2020-8162)

  - rubygem-actionpack: possible strong parameters bypass (CVE-2020-8164)

  - rubygem-activesupport: potentially unintended unmarshalling of user-provided objects in MemCacheStore and
    RedisCacheStore (CVE-2020-8165)

  - rubygem-actionpack: ability to forge per-form CSRF tokens given a global CSRF token (CVE-2020-8166)

  - rubygem-actionview: CSRF vulnerability in rails-ujs (CVE-2020-8167)

  - rubygem-rails: untrusted users able to run pending migrations in production (CVE-2020-8185)

  - django: potential SQL injection via tolerance parameter in GIS functions and aggregates on Oracle
    (CVE-2020-9402)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2015-1820");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2015-3448");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2017-2662");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-1000119");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16782");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-18874");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8162");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8164");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8165");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8166");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8167");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8185");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-9402");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11612");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14335");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-15169");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25633");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:1313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1205291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1240982");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1434106");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1534027");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1772014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1789100");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1810088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1816216");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1842634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1843005");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1843072");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1843084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1843152");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1852380");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1858302");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1877566");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1879042");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9402");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 79, 89, 119, 200, 201, 209, 250, 352, 385, 400, 416, 532, 862);

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible-collection-redhat-satellite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible-runner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansiblerole-foreman_scap_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansiblerole-insights-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansiblerole-satellite-receptor-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:crane-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:createrepo_c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:createrepo_c-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-bootloaders-redhat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-bootloaders-redhat-tftpboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-discovery-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-discovery-image-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-discovery-image-service-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-dynflow-sidekiq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-gce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-installer-katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-journald");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-openstack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-ovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-proxy-content");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-proxy-journald");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-proxy-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-telemetry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hfsplus-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-certs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-client-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:keycloak-httpd-client-install");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kobo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcomps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmodulemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmodulemd2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsolv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwebsockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:livecd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_xsendfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ostree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcp-mmvstatsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-admin-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-docker-admin-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-docker-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-maintenance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-nodes-child");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-nodes-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-nodes-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-ostree-admin-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-ostree-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-puppet-admin-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-puppet-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-puppet-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-rpm-admin-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-rpm-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulpcore-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet-agent-oauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet-foreman_scap_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppetlabs-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppetserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pycairo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-blinker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gnupg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gofer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gofer-qpid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-imgcreate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-kid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-mongoengine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-nectar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-oauth2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-agent-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-client-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-docker-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-integrity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-oid_validation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-ostree-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-puppet-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-repoauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-rpm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-streamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pymongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pymongo-gridfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid-proton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-saslwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-semantic_version");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-simplejson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-zope-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-amqp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-ansible-runner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-anyjson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-billiard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-celery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-click");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-crane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-flask");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-future");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-gobject-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-isodate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-itsdangerous");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-jmespath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-keycloak-httpd-client-install");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-kombu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-lockfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-markupsafe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-okaara");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-pexpect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-psutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-ptyprocess");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-pycurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-twisted");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-vine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-werkzeug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-aiodns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-aiofiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-aiohttp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-async-timeout");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-attrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-backoff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-cairo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-certifi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-cffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-click");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-createrepo_c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-dateutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-defusedxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-diff-match-patch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-django-currentuser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-django-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-django-guardian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-django-import-export");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-django-lifecycle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-django-prometheus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-django-readonly-field");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-djangorestframework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-djangorestframework-queryfields");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-drf-access-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-drf-nested-routers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-drf-spectacular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-dynaconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-ecdsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-et-xmlfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-future");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-gnupg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-gobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-gobject-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-gunicorn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-idna-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-importlib-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-inflection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-iniparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-jdcal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-jsonschema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-libcomps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-markuppy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-markupsafe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-mongoengine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-multidict");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-odfpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-openpyxl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-productmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-prometheus-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-psycopg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pulp-2to3-migration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pulp-certguard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pulp-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pulp-file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pulp-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pulpcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pyOpenSSL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pycares");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pycparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pycryptodomex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pygtrie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pyjwkest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pyjwt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pymongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pyrsistent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pytz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-pyyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-receptor-satellite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-rq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-semantic-version");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-sqlparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-subscription-manager-rhsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-tablib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-typing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-typing-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-uritemplate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-url-normalize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-urlman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-whitenoise");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-xlrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-xlwt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-yarl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-zipp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-client-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-cpp-server-linearstore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-dispatch-router");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-dispatch-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-proton-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-qmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qpid-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:receptor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-access-insights-puppet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:repoview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-postgresql12-postgresql-evr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhel8-kickstart-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-facter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fast_gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_scap_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-highline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-oauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger-native-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:saslwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-capsule");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-debug-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-actioncable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-actionmailbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-actionmailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-actiontext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-actionview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-activejob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-activemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-activerecord-import");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-activerecord-session_store");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-activestorage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-activesupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-addressable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-algebrick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-amazing_print");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ancestry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-anemone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-angular-rails-templates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ansi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-apipie-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-apipie-dsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-apipie-params");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-apipie-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-audited");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-azure_mgmt_compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-azure_mgmt_network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-azure_mgmt_resources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-azure_mgmt_storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-azure_mgmt_subscriptions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-bcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-bundler_ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-clamp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-coffee-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-coffee-script");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-coffee-script-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-concurrent-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-concurrent-ruby-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-connection_pool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-crass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-css_parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-deacon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-declarative");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-declarative-option");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-deep_cloneable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-deface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-diffy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-domain_name");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-dynflow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-erubi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-excon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-execjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-facter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-faraday");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-faraday-cookie_jar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-faraday_middleware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fast_gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-google");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-kubevirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-openstack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-ovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-vsphere");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fog-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman-tasks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman-tasks-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_ansible_core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_azure_rm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_bootdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_hooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_kubevirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_leapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_remote_execution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_remote_execution-cockpit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_remote_execution_core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_rh_cloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_templates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_theme_satellite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-foreman_virt_who_configure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-formatador");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-friendly_id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-fx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-get_process_mem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-gettext_i18n_rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-gitlab-sidekiq-fetcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-globalid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-google-api-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-google-cloud-env");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-googleauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-graphql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-graphql-batch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_azure_rm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_bootdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_kubevirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_leapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_remote_execution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_tasks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_templates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_foreman_virt_who_configure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hammer_cli_katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-hashie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-highline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-http-cookie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-http-form_data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-http_parser.rb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-httpclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-infoblox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ipaddress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-jgrep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-journald-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-journald-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-jwt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-kafo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-kafo_parsers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-kafo_wizards");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-kubeclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ldap_fluff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-little-plugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-logging-journald");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-loofah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-marcel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-memoist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-method_source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-mime-types");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-mime-types-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-mimemagic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-mini_mime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-mini_portile2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ms_rest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ms_rest_azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-multi_json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-multipart-post");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-mustermann");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-net-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-net-ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-net-scp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-net-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-net-ssh-krb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-netrc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-newt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-nio4r");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-nokogiri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-oauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-optimist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-os");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ovirt-engine-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ovirt_provision_plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-parse-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-passenger-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-passenger-native-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-polyglot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-powerbar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-prometheus-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-promise.rb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-public_suffix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-pulp_2to3_migration_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-pulp_ansible_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-pulp_certguard_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-pulp_container_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-pulp_deb_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-pulp_file_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-pulp_rpm_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-pulpcore_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-puma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-puma-plugin-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-quantile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rabl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rack-cors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rack-jsonp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rack-protection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rack-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rails-dom-testing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rails-html-sanitizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rails-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-railties");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rainbow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rb-inotify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rbovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rbvmomi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-record_tag_helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-recursive-open-struct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-redfish_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-redhat_access");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-redhat_access_lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-representable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-responders");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rest-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-retriable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rkerberos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-roadie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-roadie-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-robotex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rsec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ruby-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ruby2ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-ruby_parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-rubyipmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-runcible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-safemode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-scoped_search");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-sd_notify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-secure_headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-sequel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-server_sent_events");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-sexp_processor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-sidekiq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-signet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-sinatra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-smart_proxy_ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-smart_proxy_dhcp_infoblox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-smart_proxy_dhcp_remote_isc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-smart_proxy_discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-smart_proxy_discovery_image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-smart_proxy_dns_infoblox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-smart_proxy_dynflow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-smart_proxy_dynflow_core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-smart_proxy_openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-smart_proxy_pulp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-smart_proxy_remote_execution_ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-sprockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-sprockets-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-sshkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-statsd-instrument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-stomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-text");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-thor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-thread_safe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-tilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-timeliness");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-tzinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-uber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-unf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-unf_ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-unicode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-unicode-display_width");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-validates_lengths_from_database");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-webpack-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-websocket-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-websocket-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-will_paginate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-rubygem-zeitwerk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tfm-runtime");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7Server/x86_64/sat-capsule/6.9/debug',
      'content/dist/rhel/server/7/7Server/x86_64/sat-capsule/6.9/os',
      'content/dist/rhel/server/7/7Server/x86_64/sat-capsule/6.9/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/satellite/6.9/debug',
      'content/dist/rhel/server/7/7Server/x86_64/satellite/6.9/os',
      'content/dist/rhel/server/7/7Server/x86_64/satellite/6.9/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ansible-collection-redhat-satellite-2.0.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'ansible-runner-1.4.6-1.el7ar', 'release':'7', 'el_string':'el7ar', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'ansiblerole-foreman_scap_client-0.1.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'ansiblerole-insights-client-1.7.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'ansiblerole-satellite-receptor-installer-0.6.13-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'candlepin-3.1.26-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'candlepin-selinux-3.1.26-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'crane-selinux-3.5.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'createrepo_c-0.17.1-1.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'createrepo_c-libs-0.17.1-1.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'foreman-2.3.1.20-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'foreman-bootloaders-redhat-202005201200-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'foreman-bootloaders-redhat-tftpboot-202005201200-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'foreman-cli-2.3.1.20-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'foreman-debug-2.3.1.20-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'foreman-discovery-image-3.7.4-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6'},
      {'reference':'foreman-discovery-image-service-1.0.0-4.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'foreman-discovery-image-service-tui-1.0.0-4.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'foreman-dynflow-sidekiq-2.3.1.20-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'foreman-ec2-2.3.1.20-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'foreman-gce-2.3.1.20-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'foreman-installer-2.3.1.10-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6'},
      {'reference':'foreman-installer-katello-2.3.1.10-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6'},
      {'reference':'foreman-journald-2.3.1.20-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'foreman-libvirt-2.3.1.20-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'foreman-openstack-2.3.1.20-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'foreman-ovirt-2.3.1.20-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'foreman-postgresql-2.3.1.20-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'foreman-proxy-2.3.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'foreman-proxy-content-3.18.1-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'foreman-proxy-journald-2.3.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'foreman-proxy-selinux-2.3.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'foreman-selinux-2.3.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'foreman-service-2.3.1.20-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'foreman-telemetry-2.3.1.20-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'foreman-vmware-2.3.1.20-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'hfsplus-tools-332.14-12.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'katello-3.18.1-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'katello-certs-tools-2.7.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'katello-client-bootstrap-1.7.5-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'katello-common-3.18.1-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'katello-debug-3.18.1-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'katello-selinux-3.5.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'keycloak-httpd-client-install-1.2.2-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'kobo-0.5.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'libcomps-0.1.15-1.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'libmodulemd-1.7.0-1.pulp.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'libmodulemd2-2.9.3-1.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'libsolv-0.7.12-2.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'libwebsockets-2.4.2-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'livecd-tools-20.4-1.6.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6'},
      {'reference':'mod_passenger-4.0.18-24.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'mod_xsendfile-0.12-11.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'ostree-2017.1-2.atomic.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'pcp-mmvstatsd-0.4-2.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'pulp-admin-client-2.21.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'pulp-docker-admin-extensions-3.2.9-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'pulp-docker-plugins-3.2.9-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'pulp-katello-1.0.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'pulp-maintenance-2.21.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'pulp-nodes-child-2.21.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'pulp-nodes-common-2.21.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'pulp-nodes-parent-2.21.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'pulp-ostree-admin-extensions-1.3.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'pulp-ostree-plugins-1.3.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'pulp-puppet-admin-extensions-2.21.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'pulp-puppet-plugins-2.21.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'pulp-puppet-tools-2.21.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'pulp-rpm-admin-extensions-2.21.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'pulp-rpm-plugins-2.21.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'pulp-selinux-2.21.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'pulp-server-2.21.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'pulpcore-selinux-1.2.3-2.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'puppet-agent-6.19.1-2.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'puppet-agent-oauth-0.5.1-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'puppet-foreman_scap_client-0.4.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'puppetlabs-stdlib-5.2.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'puppetserver-6.14.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'pycairo-1.16.3-9.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-blinker-1.3-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-bson-3.2-2.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-gnupg-0.3.7-1.el7ui', 'release':'7', 'el_string':'el7ui', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-gofer-2.12.5-7.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-gofer-qpid-2.12.5-7.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-imgcreate-20.4-1.6.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6'},
      {'reference':'python-kid-0.9.6-11.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-mongoengine-0.10.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-nectar-1.6.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-oauth2-1.5.211-8.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-pulp-agent-lib-2.21.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-pulp-bindings-2.21.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-pulp-client-lib-2.21.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-pulp-common-2.21.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-pulp-docker-common-3.2.9-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-pulp-integrity-2.21.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-pulp-oid_validation-2.21.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-pulp-ostree-common-1.3.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-pulp-puppet-common-2.21.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-pulp-repoauth-2.21.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-pulp-rpm-common-2.21.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-pulp-streamer-2.21.5-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-pymongo-3.2-2.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-pymongo-gridfs-3.2-2.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-qpid-1.35.0-5.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-qpid-proton-0.28.0-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-qpid-qmf-1.36.0-28.el7amq', 'cpu':'x86_64', 'release':'7', 'el_string':'el7amq', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-saslwrapper-0.22-5.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-semantic_version-2.2.0-6.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-simplejson-3.2.0-1.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python-zope-interface-4.0.5-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-amqp-2.2.2-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-ansible-runner-1.4.6-1.el7ar', 'release':'7', 'el_string':'el7ar', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-anyjson-0.3.3-11.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-billiard-3.5.0.3-3.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6'},
      {'reference':'python2-celery-4.0.2-9.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-click-6.7-9.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-crane-3.3.1-9.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-daemon-2.1.2-7.el7at', 'release':'7', 'el_string':'el7at', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-django-1.11.29-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-flask-0.12.2-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6'},
      {'reference':'python2-future-0.16.0-11.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-gobject-3.28.3-2.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-gobject-base-3.28.3-2.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-isodate-0.5.4-12.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-itsdangerous-0.24-15.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-jinja2-2.10-10.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-jmespath-0.9.0-6.el7_7', 'release':'7', 'el_string':'el7_7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-keycloak-httpd-client-install-1.2.2-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-kombu-4.0.2-14.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'satellite-6'},
      {'reference':'python2-lockfile-0.11.0-10.el7ar', 'release':'7', 'el_string':'el7ar', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6'},
      {'reference':'python2-markupsafe-0.23-21.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-okaara-1.0.37-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-pexpect-4.6-1.el7at', 'release':'7', 'el_string':'el7at', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-psutil-5.7.2-2.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-ptyprocess-0.5.2-3.el7at', 'release':'7', 'el_string':'el7at', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-pycurl-7.43.0.2-4.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-solv-0.7.12-2.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-twisted-16.4.1-12.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python2-vine-1.1.3-6.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'satellite-6'},
      {'reference':'python2-werkzeug-0.12.2-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-aiodns-2.0.0-3.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-aiofiles-0.6.0-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-aiohttp-3.6.2-4.el7ar', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ar', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-async-timeout-3.0.1-2.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-attrs-19.3.0-2.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-backoff-1.10.0-3.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-cairo-1.10.0-25.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-certifi-2020.6.20-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-cffi-1.14.3-1.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-chardet-3.0.4-10.el7ar', 'release':'7', 'el_string':'el7ar', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-chardet-3.0.4-3.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-click-7.1.2-3.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-createrepo_c-0.17.1-1.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-cryptography-2.9.2-1.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-dateutil-2.8.1-3.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-defusedxml-0.6.0-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-diff-match-patch-20200713-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-django-2.2.18-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-django-currentuser-0.5.1-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-django-filter-2.3.0-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-django-guardian-2.3.0-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-django-import-export-2.3.0-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-django-lifecycle-0.8.0-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-django-prometheus-2.1.0-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-django-readonly-field-1.0.5-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-djangorestframework-3.11.2-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-djangorestframework-queryfields-1.0.0-3.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-drf-access-policy-0.7.0-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-drf-nested-routers-0.91-2.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-drf-spectacular-0.9.13-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-dynaconf-3.1.2-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-ecdsa-0.13.3-2.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-et-xmlfile-1.0.1-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-future-0.18.2-3.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-gnupg-0.4.6-3.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-gobject-3.22.0-8.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-gobject-base-3.22.0-8.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-gunicorn-20.0.4-2.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-idna-2.10-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-idna-ssl-1.1.0-3.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-importlib-metadata-1.7.0-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-inflection-0.5.1-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-iniparse-0.4-33.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-jdcal-1.4.1-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-jinja2-2.11.2-3.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-jsonschema-3.2.0-4.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-libcomps-0.1.15-1.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-markuppy-1.14-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-markupsafe-1.1.1-4.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-mongoengine-0.20.0-3.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-multidict-4.7.6-1.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-odfpy-1.4.1-2.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-openpyxl-3.0.5-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-productmd-1.31-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-prometheus-client-0.7.1-2.el7ar', 'release':'7', 'el_string':'el7ar', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-psycopg2-2.8.6-1.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-pulp-2to3-migration-0.10.0-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-pulp-certguard-1.0.3-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-pulp-container-2.1.1-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-pulp-file-1.3.0-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-pulp-rpm-3.9.0-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-pulpcore-3.7.3-2.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-pycares-3.1.1-2.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-pycparser-2.20-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-pycryptodomex-3.9.8-1.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-pygtrie-2.3.3-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-pyjwkest-1.4.2-2.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-pyjwt-1.7.1-3.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-pymongo-3.11.0-3.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-pyOpenSSL-19.1.0-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-pyrsistent-0.17.3-1.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-pytz-2020.4-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-pyyaml-5.3.1-3.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-receptor-satellite-1.3.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-redis-3.5.3-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-requests-2.24.0-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-rpm-4.11.3-8.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-rq-1.5.2-2.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-semantic-version-2.8.5-3.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-six-1.15.0-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-solv-0.7.12-2.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-sqlparse-0.4.1-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-subscription-manager-rhsm-1.27.5-4.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-tablib-2.0.0-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-typing-3.7.4.3-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-typing-extensions-3.7.4.3-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-uritemplate-3.0.1-2.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-url-normalize-1.4.3-2.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-urllib3-1.25.11-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-urlman-1.3.0-2.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-whitenoise-5.2.0-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-xlrd-1.2.0-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-xlwt-1.3.0-1.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-yarl-1.6.2-1.el7pc', 'cpu':'x86_64', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'python3-zipp-3.4.0-2.el7pc', 'release':'7', 'el_string':'el7pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'qpid-cpp-client-1.36.0-28.el7amq', 'cpu':'x86_64', 'release':'7', 'el_string':'el7amq', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'qpid-cpp-client-devel-1.36.0-28.el7amq', 'cpu':'x86_64', 'release':'7', 'el_string':'el7amq', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'qpid-cpp-server-1.36.0-28.el7amq', 'cpu':'x86_64', 'release':'7', 'el_string':'el7amq', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'qpid-cpp-server-linearstore-1.36.0-28.el7amq', 'cpu':'x86_64', 'release':'7', 'el_string':'el7amq', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'qpid-dispatch-router-1.5.0-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'qpid-dispatch-tools-1.5.0-4.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'qpid-proton-c-0.28.0-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'qpid-qmf-1.36.0-28.el7amq', 'cpu':'x86_64', 'release':'7', 'el_string':'el7amq', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'qpid-tools-1.36.0-28.el7amq', 'release':'7', 'el_string':'el7amq', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'receptor-0.6.3-1.el7ar', 'release':'7', 'el_string':'el7ar', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'redhat-access-insights-puppet-1.0.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'repoview-0.6.6-11.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'rh-postgresql12-postgresql-evr-0.0.2-1.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'rhel8-kickstart-setup-0.0.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'rubygem-facter-2.4.1-2.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'rubygem-fast_gettext-1.1.0-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'rubygem-foreman_scap_client-0.4.7-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'rubygem-highline-1.7.8-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'rubygem-oauth-0.5.4-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'rubygem-passenger-4.0.18-24.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'rubygem-passenger-native-4.0.18-24.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'rubygem-passenger-native-libs-4.0.18-24.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'rubygem-rack-1.6.12-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6'},
      {'reference':'rubygem-rake-0.9.2.2-41.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'saslwrapper-0.22-5.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'satellite-6.9.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'satellite-capsule-6.9.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'satellite-cli-6.9.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'satellite-common-6.9.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'satellite-debug-tools-6.9.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'satellite-installer-6.9.0.10-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-actioncable-6.0.3.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-actionmailbox-6.0.3.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-actionmailer-6.0.3.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-actionpack-6.0.3.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-actiontext-6.0.3.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-actionview-6.0.3.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-activejob-6.0.3.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-activemodel-6.0.3.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-activerecord-6.0.3.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-activerecord-import-1.0.0-6.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-activerecord-session_store-1.1.1-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-activestorage-6.0.3.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-activesupport-6.0.3.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-addressable-2.6.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-algebrick-0.7.3-6.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-amazing_print-1.1.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-ancestry-3.0.7-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-anemone-0.7.2-22.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-angular-rails-templates-1.1.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-ansi-1.5.0-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-apipie-bindings-0.4.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-apipie-dsl-2.3.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-apipie-params-0.0.5-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-apipie-rails-0.5.17-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-audited-4.9.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-azure_mgmt_compute-0.18.7-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-azure_mgmt_network-0.19.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-azure_mgmt_resources-0.17.6-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-azure_mgmt_storage-0.17.10-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-azure_mgmt_subscriptions-0.18.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-bcrypt-3.1.12-1.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-builder-3.2.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-bundler_ext-0.4.1-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-clamp-1.1.2-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-coffee-rails-5.0.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-coffee-script-2.4.1-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-coffee-script-source-1.12.2-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-concurrent-ruby-1.1.6-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-concurrent-ruby-edge-0.6.0-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-connection_pool-2.2.2-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-crass-1.0.6-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-css_parser-1.4.7-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-daemons-1.2.3-7.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-deacon-1.0.0-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-declarative-0.0.10-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-declarative-option-0.1.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-deep_cloneable-3.0.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-deface-1.5.3-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-diffy-3.0.1-6.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-domain_name-0.5.20160310-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-dynflow-1.4.7-1.fm2_1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-erubi-1.9.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-excon-0.76.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-execjs-2.7.0-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-facter-2.4.0-6.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-faraday-0.17.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-faraday-cookie_jar-0.0.6-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-faraday_middleware-0.13.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-fast_gettext-1.4.1-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-ffi-1.12.2-1.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-fog-aws-3.6.5-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-fog-core-2.1.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-fog-google-1.11.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-fog-json-1.2.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-fog-kubevirt-1.3.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-fog-libvirt-0.7.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-fog-openstack-1.0.8-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-fog-ovirt-1.2.5-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-fog-vsphere-3.4.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-fog-xml-0.1.2-8.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-foreman-tasks-3.0.5-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-foreman-tasks-core-0.3.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-foreman_ansible-6.1.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-foreman_ansible_core-4.0.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-foreman_azure_rm-2.1.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-foreman_bootdisk-17.0.2-2.fm2_1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-foreman_discovery-16.3.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-foreman_hooks-0.3.17-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-foreman_kubevirt-0.1.8-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-foreman_leapp-0.1.6-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-foreman_openscap-4.1.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-foreman_remote_execution-4.2.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-foreman_remote_execution-cockpit-4.2.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-foreman_remote_execution_core-1.4.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-foreman_rh_cloud-3.0.18.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-foreman_templates-9.0.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-foreman_theme_satellite-7.0.1.5-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-foreman_virt_who_configure-0.5.5-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-formatador-0.2.1-11.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-friendly_id-5.3.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-fx-0.5.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-get_process_mem-0.2.1-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-gettext-3.1.4-10.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-gettext_i18n_rails-1.8.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-git-1.5.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-gitlab-sidekiq-fetcher-0.6.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-globalid-0.4.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-google-api-client-0.33.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-google-cloud-env-1.3.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-googleauth-0.13.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-graphql-1.8.14-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-graphql-batch-0.3.10-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-gssapi-1.2.0-6.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-hammer_cli-2.3.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-hammer_cli_foreman-2.3.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-hammer_cli_foreman_admin-0.0.9-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-hammer_cli_foreman_ansible-0.3.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-hammer_cli_foreman_azure_rm-0.2.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-hammer_cli_foreman_bootdisk-0.3.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-hammer_cli_foreman_discovery-1.0.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-hammer_cli_foreman_docker-0.0.7-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-hammer_cli_foreman_kubevirt-0.1.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-hammer_cli_foreman_leapp-0.1.0-2.fm2_1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-hammer_cli_foreman_openscap-0.1.12-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-hammer_cli_foreman_remote_execution-0.2.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-hammer_cli_foreman_tasks-0.0.15-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-hammer_cli_foreman_templates-0.2.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-hammer_cli_foreman_virt_who_configure-0.0.7-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-hammer_cli_katello-0.24.0.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-hashie-3.6.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-highline-1.7.8-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-http-3.3.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-http-cookie-1.0.2-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-http-form_data-2.1.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-http_parser.rb-0.6.0-1.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-httpclient-2.8.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-i18n-1.8.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-infoblox-3.0.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-ipaddress-0.8.0-11.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-jgrep-1.3.3-12.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-journald-logger-2.0.4-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-journald-native-1.0.11-2.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-jwt-2.2.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-kafo-6.2.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-kafo_parsers-1.1.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-kafo_wizards-0.0.1-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-katello-3.18.1.22-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-kubeclient-4.3.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-ldap_fluff-0.4.7-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-little-plugger-1.1.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-locale-2.0.9-13.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-logging-2.3.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-logging-journald-2.0.0-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-loofah-2.4.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-mail-2.7.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-marcel-0.3.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-memoist-0.16.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-method_source-0.9.2-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-mime-types-3.2.2-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-mime-types-data-3.2018.0812-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-mimemagic-0.3.5-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-mini_mime-1.0.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-mini_portile2-2.4.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-ms_rest-0.7.4-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-ms_rest_azure-0.11.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-multi_json-1.14.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-multipart-post-2.0.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-mustermann-1.0.2-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-net-ldap-0.16.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-net-ping-2.0.1-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-net-scp-1.2.1-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-net-ssh-4.2.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-net-ssh-krb-0.4.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-netrc-0.11.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-newt-0.9.7-2.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-nio4r-2.5.4-1.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-nokogiri-1.10.9-1.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-oauth-0.5.4-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-openscap-0.4.9-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-optimist-3.0.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-os-1.0.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-ovirt-engine-sdk-4.3.0-1.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-ovirt_provision_plugin-2.0.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-parse-cron-0.1.4-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-passenger-4.0.18-26.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-passenger-native-4.0.18-26.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-passenger-native-libs-4.0.18-26.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-pg-1.1.4-2.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-polyglot-0.3.5-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-powerbar-2.0.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-prometheus-client-1.0.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-promise.rb-0.7.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-public_suffix-3.0.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-pulp_2to3_migration_client-0.7.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-pulp_ansible_client-0.4.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-pulp_certguard_client-1.0.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-pulp_container_client-2.1.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-pulp_deb_client-2.7.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-pulp_file_client-1.3.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-pulp_rpm_client-3.9.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-pulpcore_client-3.7.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-puma-4.3.6-1.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-puma-plugin-systemd-0.1.5-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-quantile-0.2.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-rabl-0.14.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-rack-2.2.3-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-rack-cors-1.0.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-rack-jsonp-1.3.1-9.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-rack-protection-2.0.3-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-rack-test-1.1.0-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-rails-6.0.3.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-rails-dom-testing-2.0.3-6.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-rails-html-sanitizer-1.3.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-rails-i18n-6.0.0-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-railties-6.0.3.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-rainbow-2.2.1-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-rb-inotify-0.9.7-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-rbovirt-0.1.7-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-rbvmomi-2.2.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-record_tag_helper-1.0.1-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-recursive-open-struct-1.1.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-redfish_client-0.5.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-redhat_access-2.2.19-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-redhat_access_lib-1.1.5-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-redis-4.1.2-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-representable-3.0.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-responders-3.0.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-rest-client-2.0.2-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-retriable-3.1.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-rkerberos-0.1.5-18.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-roadie-3.4.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-roadie-rails-2.1.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-robotex-1.0.0-21.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-rsec-0.4.3-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-ruby-libvirt-0.7.1-1.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-ruby2ruby-2.4.2-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-ruby_parser-3.10.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-rubyipmi-0.10.0-6.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-runcible-2.13.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-safemode-1.3.6-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-scoped_search-4.1.9-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-sd_notify-0.1.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-secure_headers-6.3.0-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-sequel-5.7.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-server_sent_events-0.1.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-sexp_processor-4.10.0-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-sidekiq-5.2.7-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-signet-0.14.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-sinatra-2.0.3-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-smart_proxy_ansible-3.0.1-6.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-smart_proxy_dhcp_infoblox-0.0.16-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-smart_proxy_dhcp_remote_isc-0.0.5-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-smart_proxy_discovery-1.0.5-6.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-smart_proxy_discovery_image-1.3.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-smart_proxy_dns_infoblox-1.1.0-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-smart_proxy_dynflow-0.3.0-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-smart_proxy_dynflow_core-0.3.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-smart_proxy_openscap-0.7.4-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-smart_proxy_pulp-2.1.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-smart_proxy_remote_execution_ssh-0.3.1-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-sprockets-4.0.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-sprockets-rails-3.2.1-6.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-sqlite3-1.3.13-5.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-sshkey-1.9.0-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-statsd-instrument-2.1.4-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-stomp-1.4.9-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-text-1.3.0-7.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-thor-1.0.1-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-thread_safe-0.3.6-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-tilt-2.0.8-4.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-timeliness-0.3.10-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-tzinfo-1.2.6-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-uber-0.1.0-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-unf-0.1.3-7.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-unf_ext-0.0.7.2-1.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-unicode-0.4.4.4-1.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-unicode-display_width-1.0.5-5.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-validates_lengths_from_database-0.5.0-7.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-webpack-rails-0.9.8-6.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-websocket-driver-0.7.1-1.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-websocket-extensions-0.1.5-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-will_paginate-3.1.7-3.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-xmlrpc-0.3.0-2.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-rubygem-zeitwerk-2.2.2-1.el7sat', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'},
      {'reference':'tfm-runtime-6.1-4.el7sat', 'cpu':'x86_64', 'release':'7', 'el_string':'el7sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6'}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ansible-collection-redhat-satellite / ansible-runner / etc');
}

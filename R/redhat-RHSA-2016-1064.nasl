#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1064. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119372);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/11");

  script_cve_id("CVE-2016-2149", "CVE-2016-2160", "CVE-2016-3711");
  script_xref(name:"RHSA", value:"2016:1064");

  script_name(english:"RHEL 7 : Red Hat OpenShift Enterprise 3.2 (RHSA-2016:1064)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Red Hat OpenShift Enterprise 3.2 is now available.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

OpenShift Enterprise by Red Hat is the company's cloud computing
Platform- as-a-Service (PaaS) solution designed for on-premise or
private cloud deployments.

Security Fix(es) :

* A flaw was found in the building of containers within OpenShift
Enterprise. An attacker could submit an image for building that
executes commands within the container as root, allowing them to
potentially escalate privileges. (CVE-2016-2160)

* It was found that OpenShift Enterprise would disclose log file
contents from reclaimed namespaces. An attacker could create a new
namespace to access log files present in a previously deleted
namespace using the same name. (CVE-2016-2149)

* An information disclosure flaw was discovered in haproxy as used by
OpenShift Enterprise; a cookie with the name 'OPENSHIFT_[namespace]
_SERVERID' was set, which contained the internal IP address of a pod.
(CVE-2016-3711)

The CVE-2016-2149 issue was discovered by Wesley Hearn (Red Hat).

Additional Changes :

* Space precludes documenting all of the bug fixes and enhancements in
this advisory. For details on all new features, bug fixes, and known
issues, see the OpenShift Enterprise 3.2 Release Notes linked to in
the References section.

This update includes the following images :

openshift3/ose:v3.2.0.20-3 openshift3/ose-deployer:v3.2.0.20-3
openshift3/ose-docker-builder:v3.2.0.20-3
openshift3/ose-docker-registry:v3.2.0.20-3
openshift3/ose-f5-router:v3.2.0.20-3
openshift3/ose-haproxy-router:v3.2.0.20-3
openshift3/ose-keepalived-ipfailover:v3.2.0.20-3
openshift3/ose-pod:v3.2.0.20-3 openshift3/ose-recycler:v3.2.0.20-3
openshift3/ose-sti-builder:v3.2.0.20-3
openshift3/image-inspector:1.0.0-12
openshift3/jenkins-1-rhel7:1.642-31
openshift3/logging-auth-proxy:3.2.0-3
openshift3/logging-deployment:3.2.0-8
openshift3/logging-elasticsearch:3.2.0-7
openshift3/logging-fluentd:3.2.0-6 openshift3/logging-kibana:3.2.0-3
openshift3/metrics-cassandra:3.2.0-4
openshift3/metrics-deployer:3.2.0-5
openshift3/metrics-hawkular-metrics:3.2.0-6
openshift3/metrics-heapster:3.2.0-5 openshift3/mongodb-24-rhel7:2.4-27
openshift3/mysql-55-rhel7:5.5-25 openshift3/nodejs-010-rhel7:0.10-34
openshift3/node:v3.2.0.20-3 openshift3/openvswitch:v3.2.0.20-4
openshift3/perl-516-rhel7:5.16-37 openshift3/php-55-rhel7:5.5-34
openshift3/postgresql-92-rhel7:9.2-24
openshift3/python-33-rhel7:3.3-34 openshift3/ruby-20-rhel7:2.0-34"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:1064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-2149"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-2160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-3711"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-clients-redistributable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-dockerregistry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-pod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-recycle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-sdn-ovs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cockpit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cockpit-kubernetes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:elastic-curator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:elasticsearch-cloud-kubernetes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fb303");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fb303-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fb303-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fluentd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fluentd-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:heapster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:http-parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:http-parser-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:http-parser-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:image-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins-plugin-credentials");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins-plugin-durable-task");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins-plugin-kubernetes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins-plugin-openshift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins-plugin-openshift-pipeline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins-plugin-promoted-builds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins-plugin-swarm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kibana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kibana-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libthrift-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libthrift-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libuv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libuv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libuv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libuv-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:lucene");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:lucene-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-abbrev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-accepts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-align-text");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-ansi-green");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-ansi-regex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-ansi-styles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-ansi-wrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-anymatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-arr-diff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-arr-flatten");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-array-flatten");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-array-unique");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-arrify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-asn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-assert-plus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-async");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-async-each");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-aws-sign2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-balanced-match");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-base64url");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-basic-auth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-binary-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-bl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-bluebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-body-parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-boom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-brace-expansion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-braces");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-bytes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-camelcase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-camelcase-keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-capture-stack-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-caseless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-center-align");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-chalk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-chokidar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-client-sessions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-cliui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-combined-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-commander");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-concat-map");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-concat-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-configstore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-content-disposition");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-content-type");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-cookie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-cookie-signature");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-cookies");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-core-util-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-create-error-class");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-cryptiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-decamelize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-deep-extend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-delayed-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-depd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-destroy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-duplexer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-duplexify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-ee-first");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-end-of-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-error-ex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-es6-promise");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-escape-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-escape-string-regexp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-etag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-event-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-eventemitter3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-expand-brackets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-expand-range");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-express");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-extend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-extglob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-filename-regex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-fill-range");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-finalhandler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-findup-sync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-for-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-for-own");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-forever-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-form-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-forwarded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-fresh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-from");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-generate-function");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-generate-object-property");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-glob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-glob-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-glob-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-got");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-graceful-fs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-graceful-readlink");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-har-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-has-ansi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-has-color");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-has-flag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-hawk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-hoek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-http-errors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-http-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-http-signature");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-iconv-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-indent-string");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-inflight");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-inherits");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-ini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-invert-kv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-ipaddr.js");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-binary-path");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-buffer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-dotfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-equal-shallow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-extendable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-extglob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-finite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-glob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-my-json-valid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-npm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-number");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-plain-obj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-primitive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-property");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-redirect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-is-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-isarray");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-isobject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-isstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-json-stringify-safe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-jsonpointer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-keygrip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-kind-of");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-latest-version");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lazy-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lcid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lodash.assign");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lodash.baseassign");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lodash.basecopy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lodash.bindcallback");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lodash.createassigner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lodash.defaults");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lodash.getnative");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lodash.isarguments");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lodash.isarray");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lodash.isiterateecall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lodash.keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lodash.restparam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-longest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-lowercase-keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-map-obj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-map-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-media-typer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-meow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-merge-descriptors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-methods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-micromatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-mime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-mime-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-mime-types");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-minimatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-minimist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-mkdirp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-morgan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-negotiator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-node-status-codes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-node-uuid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-nodemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-nopt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-normalize-path");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-number-is-nan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-oauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-oauth-sign");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-object-assign");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-object.omit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-on-finished");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-on-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-once");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-openshift-auth-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-optimist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-os-homedir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-os-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-os-tmpdir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-osenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-package-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-packaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-parse-duration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-parse-glob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-parse-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-parseurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-passport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-passport-http-bearer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-passport-oauth2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-passport-strategy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-path-is-absolute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-path-to-regexp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-patternfly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-pause");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-pause-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-pinkie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-pinkie-promise");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-prepend-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-preserve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-process-nextick-args");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-proxy-addr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-ps-tree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-qs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-randomatic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-range-parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-raw-body");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-rc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-read-all-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-readable-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-readdirp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-regex-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-registry-url");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-repeat-element");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-repeat-string");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-repeating");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-request");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-requires-port");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-resolve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-right-align");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-semver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-semver-diff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-send");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-serve-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-slide");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-sntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-split");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-statuses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-stream-combiner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-string-length");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-string_decoder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-stringstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-strip-ansi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-strip-json-comments");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-success-symbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-supports-color");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-through");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-timed-out");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-touch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-tough-cookie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-tunnel-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-type-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-typedarray");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-uid2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-undefsafe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-unpipe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-unzip-response");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-update-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-url-join");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-url-parse-lax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-util-deprecate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-utils-merge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-uuid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-vary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-window-size");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-wordwrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-wrappy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-write-file-atomic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-xdg-basedir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-xtend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-y18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs-yargs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss_wrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss_wrapper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-elasticsearch-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:origin-kibana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-thrift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php55-php-pecl-imagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php55-php-pecl-imagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php55-php-pecl-xdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php55-php-pecl-xdebug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-click");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-contextlib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-crypto-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-ecdsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-fb303");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-fixtures");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-httplib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-keyczar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-linecache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-mimeparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-nose-xcover");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-openvswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-paramiko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pbr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-testtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-testtools-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-thrift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-traceback2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-unittest2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-mock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python33-python-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-activesupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-addressable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-addressable-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-atomic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-atomic-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-atomic-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-builder-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-configuration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-configuration-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-cool.io");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-cool.io-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-cool.io-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-crack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-crack-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-dalli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-dalli-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-diff-lcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-diff-lcs-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-docker-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-docker-api-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-elasticsearch-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-elasticsearch-api-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-elasticsearch-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-elasticsearch-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-elasticsearch-extensions-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-elasticsearch-transport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-elasticsearch-transport-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-excon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-excon-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-faraday");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-faraday-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fluent-plugin-add");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fluent-plugin-add-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fluent-plugin-docker_metadata_filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fluent-plugin-docker_metadata_filter-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fluent-plugin-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fluent-plugin-elasticsearch-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fluent-plugin-flatten-hash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fluent-plugin-flatten-hash-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fluent-plugin-kubernetes_metadata_filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fluent-plugin-kubernetes_metadata_filter-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-http_parser.rb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-http_parser.rb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-http_parser.rb-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-i18n-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-introspection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-introspection-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-jnunemaker-matchy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-jnunemaker-matchy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-json_pure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-json_pure-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-kubeclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-kubeclient-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-launchy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-lru_redux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-lru_redux-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-metaclass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-metaclass-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mime-types");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mime-types-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-minitest-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mocha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mocha-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-msgpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-msgpack-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-msgpack-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-multi_json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-multi_json-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-multipart-post");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-multipart-post-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-netrc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-netrc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-recursive-open-struct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-recursive-open-struct-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rest-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rr-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rspec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rspec-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rspec-core-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rspec-expectations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rspec-expectations-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rspec-mocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rspec-mocks-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-session-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-shoulda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-shoulda-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-sigdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-sigdump-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-string-scrub");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-string-scrub-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-string-scrub-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-test-unit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-test-unit-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-test-unit-rr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-test-unit-rr-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-test_declarative");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-test_declarative-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-thread_safe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-thread_safe-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-tzinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-tzinfo-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-tzinfo-data-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-tzinfo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-webmock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-webmock-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-yajl-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-yajl-ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-yajl-ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:search-guard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sshpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sshpass-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thrift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thrift-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thrift-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tuned-profiles-atomic-openshift-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:v8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:v8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:v8-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:1064";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;

  if (! (rpm_exists(release:"RHEL7", rpm:"atomic-openshift-3.2"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenShift");

  if (rpm_check(release:"RHEL7", reference:"ansible-1.9.4-1.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-3.2.0.20-1.git.0.f44746c.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-clients-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-clients-3.2.0.20-1.git.0.f44746c.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-clients-redistributable-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-clients-redistributable-3.2.0.20-1.git.0.f44746c.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-dockerregistry-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-dockerregistry-3.2.0.20-1.git.0.f44746c.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-master-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-master-3.2.0.20-1.git.0.f44746c.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-node-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-node-3.2.0.20-1.git.0.f44746c.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-pod-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-pod-3.2.0.20-1.git.0.f44746c.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-recycle-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-recycle-3.2.0.20-1.git.0.f44746c.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-sdn-ovs-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-sdn-ovs-3.2.0.20-1.git.0.f44746c.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-tests-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-tests-3.2.0.20-1.git.0.f44746c.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"cockpit-debuginfo-0.93-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"cockpit-kubernetes-0.93-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"elastic-curator-3.5.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"elasticsearch-1.5.2.redhat_1-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"elasticsearch-cloud-kubernetes-1.2.1.redhat_1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fb303-0.9.1-12.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"fb303-devel-0.9.1-12.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"fb303-java-0.9.1-12.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"fluentd-0.12.20-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"fluentd-doc-0.12.20-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"heapster-0.18.2-4.gitaf4752e.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"http-parser-2.0-4.20121128gitcd01361.el7ost")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"http-parser-debuginfo-2.0-4.20121128gitcd01361.el7ost")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"http-parser-devel-2.0-4.20121128gitcd01361.el7ost")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"image-inspector-1.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"jenkins-1.642.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jenkins-plugin-credentials-1.24-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jenkins-plugin-durable-task-1.7-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jenkins-plugin-kubernetes-0.5-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jenkins-plugin-openshift-0.6.41-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jenkins-plugin-openshift-pipeline-1.0.9-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jenkins-plugin-promoted-builds-2.23-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jenkins-plugin-swarm-2.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kibana-4.1.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"kibana-debuginfo-4.1.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libthrift-java-0.9.1-12.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"libthrift-javadoc-0.9.1-12.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libuv-0.10.34-1.el7ost")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libuv-debuginfo-0.10.34-1.el7ost")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libuv-devel-0.10.34-1.el7ost")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libuv-static-0.10.34-1.el7ost")) flag++;
  if (rpm_check(release:"RHEL7", reference:"lucene-4.10.4.redhat_1-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"lucene-contrib-4.10.4.redhat_1-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nodejs-0.10.36-3.el7ost")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-abbrev-1.0.7-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-accepts-1.2.13-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-align-text-0.1.3-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-ansi-green-0.1.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-ansi-regex-2.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-ansi-styles-2.1.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-ansi-wrap-0.1.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-anymatch-1.3.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-arr-diff-2.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-arr-flatten-1.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-array-flatten-1.1.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-array-unique-0.2.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-arrify-1.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-asn1-0.1.11-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-assert-plus-0.1.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-async-1.4.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-async-each-1.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-aws-sign2-0.5.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-balanced-match-0.2.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-base64url-1.0.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-basic-auth-1.0.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-binary-extensions-1.3.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-bl-1.0.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-bluebird-2.10.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-body-parser-1.14.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-boom-2.8.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-brace-expansion-1.1.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-braces-1.8.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-bytes-2.1.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-camelcase-1.2.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-camelcase-keys-1.0.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-capture-stack-trace-1.0.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-caseless-0.11.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-center-align-0.1.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-chalk-1.1.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-chokidar-1.4.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-client-sessions-0.7.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-cliui-2.1.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-combined-stream-1.0.5-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-commander-2.8.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-concat-map-0.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-concat-stream-1.4.7-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-configstore-1.4.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-content-disposition-0.5.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-content-type-1.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-cookie-0.2.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-cookie-signature-1.0.6-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-cookies-0.5.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-core-util-is-1.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-create-error-class-2.0.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-cryptiles-2.0.5-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-ctype-0.5.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-debug-2.2.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nodejs-debuginfo-0.10.36-3.el7ost")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-decamelize-1.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-deep-extend-0.3.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-delayed-stream-1.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-depd-1.1.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-destroy-1.0.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nodejs-devel-0.10.36-3.el7ost")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-docs-0.10.36-3.el7ost")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-duplexer-0.1.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-duplexify-3.4.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-ee-first-1.1.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-end-of-stream-1.1.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-error-ex-1.2.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-es6-promise-3.0.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-escape-html-1.0.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-escape-string-regexp-1.0.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-etag-1.7.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-event-stream-3.3.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-eventemitter3-1.1.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-expand-brackets-0.1.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-expand-range-1.8.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-express-4.13.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-extend-3.0.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-extglob-0.3.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-filename-regex-2.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-fill-range-2.2.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-finalhandler-0.4.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-findup-sync-0.3.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-for-in-0.1.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-for-own-0.1.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-forever-agent-0.6.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-form-data-1.0.0-rc3.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-forwarded-0.1.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-fresh-0.3.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-from-0.1.3-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-generate-function-2.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-generate-object-property-1.2.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-glob-5.0.15-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-glob-base-0.3.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-glob-parent-2.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-got-5.2.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-graceful-fs-4.1.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-graceful-readlink-1.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-har-validator-1.8.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-has-ansi-2.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-has-color-0.1.7-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-has-flag-1.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-hawk-3.1.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-hoek-2.14.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-http-errors-1.3.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-http-proxy-1.11.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-http-signature-0.11.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-iconv-lite-0.4.13-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-indent-string-2.1.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-inflight-1.0.4-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-inherits-2.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-ini-1.1.0-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-invert-kv-1.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-ipaddr.js-1.0.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-binary-path-1.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-buffer-1.0.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-dotfile-1.0.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-equal-shallow-0.1.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-extendable-0.1.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-extglob-1.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-finite-1.0.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-glob-2.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-my-json-valid-2.12.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-npm-1.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-number-2.1.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-plain-obj-1.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-primitive-2.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-property-1.0.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-redirect-1.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-is-stream-1.0.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-isarray-0.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-isobject-2.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-isstream-0.1.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-json-stringify-safe-5.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-jsonpointer-2.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-keygrip-1.0.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-kind-of-3.0.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-latest-version-2.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lazy-cache-1.0.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lcid-1.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lodash.assign-3.2.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lodash.baseassign-3.2.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lodash.basecopy-3.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lodash.bindcallback-3.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lodash.createassigner-3.1.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lodash.defaults-3.1.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lodash.getnative-3.9.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lodash.isarguments-3.0.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lodash.isarray-3.0.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lodash.isiterateecall-3.0.9-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lodash.keys-3.1.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lodash.restparam-3.6.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-longest-1.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-lowercase-keys-1.0.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-map-obj-1.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-map-stream-0.1.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-media-typer-0.3.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-meow-2.0.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-merge-descriptors-1.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-methods-1.1.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-micromatch-2.3.5-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-mime-1.3.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-mime-db-1.19.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-mime-types-2.1.7-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-minimatch-3.0.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-minimist-1.2.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-mkdirp-0.5.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-morgan-1.6.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-ms-0.7.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-negotiator-0.5.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-node-status-codes-1.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-node-uuid-1.4.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-nodemon-1.8.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-nopt-3.0.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-normalize-path-2.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-number-is-nan-1.0.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-oauth-0.9.13-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-oauth-sign-0.8.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-object-assign-4.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-object.omit-2.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-on-finished-2.3.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-on-headers-1.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-once-1.3.2-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-openshift-auth-proxy-0.0.20-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-optimist-0.4.0-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-os-homedir-1.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-os-locale-1.4.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-os-tmpdir-1.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-osenv-0.1.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-package-json-2.3.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-packaging-7-1.el7ost")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-parse-duration-0.1.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-parse-glob-3.0.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-parse-json-2.2.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-parseurl-1.3.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-passport-0.2.2-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-passport-http-bearer-1.0.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-passport-oauth2-1.1.2-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-passport-strategy-1.0.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-path-is-absolute-1.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-path-to-regexp-1.2.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-patternfly-2.2.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-pause-0.0.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-pause-stream-0.0.11-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-pinkie-2.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-pinkie-promise-2.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-prepend-http-1.0.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-preserve-0.2.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-process-nextick-args-1.0.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-proxy-addr-1.0.8-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-ps-tree-1.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-qs-5.2.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-randomatic-1.1.5-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-range-parser-1.0.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-raw-body-2.1.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-rc-1.1.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-read-all-stream-3.0.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-readable-stream-2.0.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-readdirp-2.0.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-regex-cache-0.4.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-registry-url-3.0.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-repeat-element-1.1.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-repeat-string-1.5.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-repeating-2.0.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-request-2.61.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-requires-port-0.0.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-resolve-1.1.6-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-right-align-0.1.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-semver-5.1.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-semver-diff-2.1.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-send-0.13.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-serve-static-1.10.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-slide-1.1.5-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-sntp-1.0.9-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-split-0.3.3-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-statuses-1.2.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-stream-combiner-0.2.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-string-length-1.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-string_decoder-0.10.31-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-stringstream-0.0.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-strip-ansi-3.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-strip-json-comments-1.0.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-success-symbol-0.1.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-supports-color-3.1.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-through-2.3.4-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-timed-out-2.0.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-touch-1.0.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-tough-cookie-2.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-tunnel-agent-0.4.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-type-is-1.6.9-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-typedarray-0.0.6-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-uid2-0.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-undefsafe-0.0.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-unpipe-1.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-unzip-response-1.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-update-notifier-0.6.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-url-join-0.0.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-url-parse-lax-1.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-util-deprecate-1.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-utils-merge-1.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-uuid-2.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-vary-1.0.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-window-size-0.1.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-wordwrap-1.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-wrappy-1.0.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-write-file-atomic-1.1.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-xdg-basedir-2.0.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-xtend-4.0.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-y18n-3.1.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"nodejs-yargs-3.24.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nss_wrapper-1.0.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nss_wrapper-debuginfo-1.0.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"openshift-elasticsearch-plugin-0.13.0.redhat_1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openvswitch-2.4.0-2.el7_2")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openvswitch-debuginfo-2.4.0-2.el7_2")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openvswitch-devel-2.4.0-2.el7_2")) flag++;
  if (rpm_check(release:"RHEL7", reference:"openvswitch-test-2.4.0-2.el7_2")) flag++;
  if (rpm_check(release:"RHEL7", reference:"origin-kibana-0.5.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"perl-thrift-0.9.1-12.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"php55-php-pecl-imagick-3.1.2-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"php55-php-pecl-imagick-debuginfo-3.1.2-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"php55-php-pecl-xdebug-2.2.7-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"php55-php-pecl-xdebug-debuginfo-2.2.7-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-click-4.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-contextlib2-0.5.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-crypto-2.6.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-crypto-debuginfo-2.6.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-ecdsa-0.11-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-elasticsearch-2.3.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-extras-0.0.3-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-fb303-0.9.1-12.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-fixtures-0.3.14-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-httplib2-0.9.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-keyczar-0.71c-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-linecache2-1.0.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-mimeparse-0.1.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-nose-xcover-1.0.10-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-openvswitch-2.4.0-2.el7_2")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-paramiko-1.15.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-pbr-1.8.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-setuptools-17.1.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-testtools-1.1.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-testtools-doc-1.1.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-thrift-0.9.1-12.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-traceback2-1.4.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-unittest2-1.1.0-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python2-mock-1.0.1-9.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python33-python-pip-1.5.6-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-activesupport-4.2.4-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-addressable-2.3.6-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-addressable-doc-2.3.6-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-atomic-1.1.16-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-atomic-debuginfo-1.1.16-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-atomic-doc-1.1.16-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-builder-3.1.4-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-builder-doc-3.1.4-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-configuration-1.3.2-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-configuration-doc-1.3.2-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-cool.io-1.2.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-cool.io-debuginfo-1.2.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-cool.io-doc-1.2.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-crack-0.3.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-crack-doc-0.3.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-dalli-2.7.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-dalli-doc-2.7.4-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-diff-lcs-1.1.3-2.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-diff-lcs-doc-1.1.3-2.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-docker-api-1.22.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-docker-api-doc-1.22.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-elasticsearch-1.0.8-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-elasticsearch-api-1.0.7-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-elasticsearch-api-doc-1.0.7-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-elasticsearch-doc-1.0.8-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-elasticsearch-extensions-0.0.15-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-elasticsearch-extensions-doc-0.0.15-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-elasticsearch-transport-1.0.7-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-elasticsearch-transport-doc-1.0.7-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-excon-0.39.6-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-excon-doc-0.39.6-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-faraday-0.9.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-faraday-doc-0.9.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-fluent-plugin-add-0.0.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-fluent-plugin-add-doc-0.0.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-fluent-plugin-docker_metadata_filter-0.1.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-fluent-plugin-docker_metadata_filter-doc-0.1.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-fluent-plugin-elasticsearch-1.3.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-fluent-plugin-elasticsearch-doc-1.3.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-fluent-plugin-flatten-hash-0.2.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-fluent-plugin-flatten-hash-doc-0.2.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-fluent-plugin-kubernetes_metadata_filter-0.12.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-fluent-plugin-kubernetes_metadata_filter-doc-0.12.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-http_parser.rb-0.6.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-http_parser.rb-debuginfo-0.6.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-http_parser.rb-doc-0.6.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-i18n-0.7.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-i18n-doc-0.7.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-introspection-0.0.2-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-introspection-doc-0.0.2-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-jnunemaker-matchy-0.4.0-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-jnunemaker-matchy-doc-0.4.0-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-json_pure-1.6.3-9.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-json_pure-doc-1.6.3-9.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-kubeclient-0.7.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-kubeclient-doc-0.7.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-launchy-0.4.0-9.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-lru_redux-1.1.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-lru_redux-doc-1.1.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-metaclass-0.0.1-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-metaclass-doc-0.0.1-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-mime-types-1.19-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-mime-types-doc-1.19-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-minitest-4.7.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-minitest-doc-4.7.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-mocha-0.14.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-mocha-doc-0.14.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-msgpack-0.5.11-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-msgpack-debuginfo-0.5.11-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-msgpack-doc-0.5.11-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-multi_json-1.10.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-multi_json-doc-1.10.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-multipart-post-2.0.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-multipart-post-doc-2.0.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-netrc-0.7.7-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-netrc-doc-0.7.7-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-rack-1.5.2-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-rack-doc-1.5.2-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-recursive-open-struct-0.6.5-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-recursive-open-struct-doc-0.6.5-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-rest-client-1.6.7-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-rr-1.1.2-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-rr-doc-1.1.2-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-rspec-2.14.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-rspec-core-2.14.8-1.el7.0")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-rspec-core-doc-2.14.8-1.el7.0")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-rspec-expectations-2.14.5-2.el7.1")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-rspec-expectations-doc-2.14.5-2.el7.1")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-rspec-mocks-2.14.6-2.el7.1")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-rspec-mocks-doc-2.14.6-2.el7.1")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-session-3.1.0-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-session-doc-3.1.0-10.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-shoulda-2.11.3-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-shoulda-doc-2.11.3-8.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-sigdump-0.2.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-sigdump-doc-0.2.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-string-scrub-0.0.5-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-string-scrub-debuginfo-0.0.5-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-string-scrub-doc-0.0.5-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-test-unit-2.5.5-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-test-unit-doc-2.5.5-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-test-unit-rr-1.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-test-unit-rr-doc-1.0.3-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-test_declarative-0.0.5-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-test_declarative-doc-0.0.5-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-thread_safe-0.3.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-thread_safe-doc-0.3.4-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-tzinfo-1.2.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-tzinfo-data-1.2014.10-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-tzinfo-data-doc-1.2014.10-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-tzinfo-doc-1.2.2-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-webmock-1.17.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-webmock-doc-1.17.1-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-yajl-ruby-1.2.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-yajl-ruby-debuginfo-1.2.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-yajl-ruby-doc-1.2.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"search-guard-0.5.1.redhat_1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"sshpass-1.05-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"sshpass-debuginfo-1.05-5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"thrift-0.9.1-12.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"thrift-debuginfo-0.9.1-12.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"thrift-devel-0.9.1-12.el7")) flag++;
  if (rpm_exists(rpm:"tuned-profiles-atomic-openshift-node-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tuned-profiles-atomic-openshift-node-3.2.0.20-1.git.0.f44746c.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"v8-3.14.5.10-17.el7ost")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"v8-debuginfo-3.14.5.10-17.el7ost")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"v8-devel-3.14.5.10-17.el7ost")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ansible / atomic-openshift / atomic-openshift-clients / etc");
  }
}

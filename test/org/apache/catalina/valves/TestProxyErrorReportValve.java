/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.catalina.valves;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.Context;
import org.apache.catalina.Valve;
import org.apache.catalina.core.StandardHost;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;

public class TestProxyErrorReportValve extends TomcatBaseTest {

    private static final String PROXY_VALVE = ProxyErrorReportValve.class.getName();


    @Test
    public void testMissingPropertiesBundleFallsBackToSuper() throws Exception {
        Tomcat tomcat = getTomcatInstance();
        ((StandardHost) tomcat.getHost()).setErrorReportValveClass(PROXY_VALVE);

        Context ctx = getProgrammaticRootContext();

        Tomcat.addServlet(ctx, "error", new SendErrorServlet(
                HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Server broke"));
        ctx.addServletMappingDecoded("/", "error");

        tomcat.start();

        ProxyErrorReportValve valve = null;
        Valve[] valves = tomcat.getHost().getPipeline().getValves();
        for (Valve valveCandidate : valves) {
            if (PROXY_VALVE.equals(valveCandidate.getClass().getName())) {
                valve = (ProxyErrorReportValve)valveCandidate;
                break;
            }
        }
        Assert.assertNotNull(valve);
        // No ProxyErrorReportValve.properties bundle is available on the
        // test class path. The default error report must be produced rather
        // than an empty response.
        valve.setUsePropertiesFile(true);

        ByteChunk res = new ByteChunk();
        int rc = getUrl("http://localhost:" + getPort(), res, null);

        Assert.assertEquals(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, rc);

        String body = res.toString();
        Assert.assertNotNull("Response body should not be empty", body);
        Assert.assertTrue("Should contain HTML error report",
                body.contains("html") &&
                    body.contains(String.valueOf(HttpServletResponse.SC_INTERNAL_SERVER_ERROR)));
    }


    /*
     * With usePropertiesFile, the bundle lookup uses the response locale which
     * applications commonly set from the request. Unknown locales must not add
     * entries to the JVM wide ResourceBundle cache and, as no properties file
     * is available, the default error report must be used.
     */
    @Test
    public void testPropertiesFileUnknownLocaleResourceBundleCacheUsage() throws Exception {
        Tomcat tomcat = getTomcatInstance();
        StandardHost host = (StandardHost) tomcat.getHost();
        host.setErrorReportValveClass(PROXY_VALVE);

        Context ctx = getProgrammaticRootContext();

        Tomcat.addServlet(ctx, "localeError", new LocaleSendErrorServlet(HttpServletResponse.SC_NOT_FOUND));
        ctx.addServletMappingDecoded("/", "localeError");

        tomcat.start();

        ProxyErrorReportValve proxyErrorReportValve = null;
        for (Valve valve : host.getPipeline().getValves()) {
            if (valve instanceof ProxyErrorReportValve) {
                proxyErrorReportValve = (ProxyErrorReportValve) valve;
                break;
            }
        }
        Assert.assertNotNull(proxyErrorReportValve);
        proxyErrorReportValve.setUsePropertiesFile(true);

        int initial = resourceBundleCacheSize();

        final int requests = 200;
        // Use tags distinct from those used by other tests
        final int offset = 200000;
        for (int i = 0; i < requests; i++) {
            Map<String,List<String>> reqHead = new HashMap<>();
            reqHead.put("Accept-Language", Collections.singletonList(fakeLanguageTag(offset + i)));
            ByteChunk res = new ByteChunk();
            int rc = getUrl("http://localhost:" + getPort() + "/", res, reqHead, null);
            Assert.assertEquals(HttpServletResponse.SC_NOT_FOUND, rc);
            Assert.assertTrue("Should contain default error report",
                    res.toString().contains(String.valueOf(HttpServletResponse.SC_NOT_FOUND)));
        }

        int delta = resourceBundleCacheSize() - initial;
        Assert.assertTrue("ResourceBundle cache grew by " + delta + " entries for " + requests +
                " unknown response locales", delta < 50);
    }


    private static String fakeLanguageTag(int i) {
        StringBuilder tag = new StringBuilder("xxxxx");
        int v = i;
        for (int k = 4; k >= 0; k--) {
            tag.setCharAt(k, (char) ('a' + v % 26));
            v /= 26;
        }
        return tag.toString();
    }


    @SuppressWarnings("unchecked")
    private static int resourceBundleCacheSize() throws Exception {
        Field field = ResourceBundle.class.getDeclaredField("cacheList");
        field.setAccessible(true);
        Map<Object,Object> cache = (Map<Object,Object>) field.get(null);
        return cache.size();
    }


    private static final class LocaleSendErrorServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        private final int statusCode;

        private LocaleSendErrorServlet(int statusCode) {
            this.statusCode = statusCode;
        }

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws IOException {
            resp.setLocale(req.getLocale());
            resp.sendError(statusCode);
        }
    }


    private static final class SendErrorServlet extends HttpServlet {

        private static final long serialVersionUID = 1L;

        private final int statusCode;
        private final String message;

        private SendErrorServlet(int statusCode, String message) {
            this.statusCode = statusCode;
            this.message = message;
        }

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                throws IOException {
            resp.sendError(statusCode, message);
        }
    }
}

package dev.lastaperture.burp;

import burp.api.montoya.core.Version;

import java.util.LinkedHashMap;
import java.util.Map;

record BurpRuntime(String version, long buildNumber, String edition) {
    static BurpRuntime from(Version version) {
        return new BurpRuntime(version.toString(), version.buildNumber(), version.edition().name());
    }

    Map<String, Object> sourceJson() {
        Map<String, Object> source = new LinkedHashMap<>();
        source.put("api", "MONTOYA");
        source.put("build_number", buildNumber);
        source.put("edition", edition);
        source.put("tool", "BURP_SUITE");
        source.put("version", version);
        return source;
    }
}

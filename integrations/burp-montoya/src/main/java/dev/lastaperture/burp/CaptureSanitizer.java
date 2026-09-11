package dev.lastaperture.burp;

import java.net.IDN;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

final class CaptureSanitizer {
    private static final int MAX_PATH_LENGTH = 2048;
    private static final Pattern FIELD_NAME = Pattern.compile("[A-Za-z_$][A-Za-z0-9_$@.\\[\\]:-]{0,127}");
    private static final Pattern HEADER_NAME = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}");
    private static final Pattern PATH_LITERAL = Pattern.compile("[A-Za-z][A-Za-z0-9_.-]{0,63}");
    private static final Pattern VALUE_LIKE_NAME = Pattern.compile(
            "(?i)(?:[0-9]{6,}|[a-f0-9]{20,}|[a-z0-9_=-]{32,}|[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}|[0-9a-f]{8}-[0-9a-f-]{27,})");

    private CaptureSanitizer() {}

    static String canonicalOrigin(String value) {
        try {
            URI uri = new URI(requireClean(value, "origin").trim());
            String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
            if (!(scheme.equals("http") || scheme.equals("https"))) {
                throw new IllegalArgumentException("origin scheme must be http or https");
            }
            if (uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null) {
                throw new IllegalArgumentException("origin must not contain user info, query, or fragment");
            }
            if (!(uri.getRawPath() == null || uri.getRawPath().isEmpty() || uri.getRawPath().equals("/"))) {
                throw new IllegalArgumentException("origin must not contain a path");
            }
            String host = uri.getHost();
            if (host == null || host.isBlank()) throw new IllegalArgumentException("origin must contain a host");
            if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
            if (host.contains(":")) host = "[" + host.toLowerCase(Locale.ROOT) + "]";
            else host = IDN.toASCII(host).toLowerCase(Locale.ROOT);
            int port = uri.getPort();
            boolean defaultPort = port == -1 || (scheme.equals("http") && port == 80)
                    || (scheme.equals("https") && port == 443);
            return scheme + "://" + host + (defaultPort ? "" : ":" + port);
        } catch (URISyntaxException error) {
            throw new IllegalArgumentException("origin must be an absolute HTTP URL", error);
        }
    }

    static String normalizePathPrefix(String value) {
        String prefix = value == null || value.isBlank() ? "/" : requireClean(value, "path prefix").trim();
        if (!prefix.startsWith("/") || prefix.contains("?") || prefix.contains("#")) {
            throw new IllegalArgumentException("path prefix must start with / and omit query and fragment");
        }
        if (prefix.length() > MAX_PATH_LENGTH) {
            throw new IllegalArgumentException("path prefix must be at most 2048 characters");
        }
        return prefix.length() > 1 && prefix.endsWith("/") ? prefix.substring(0, prefix.length() - 1) : prefix;
    }

    static List<String> normalizePathLiterals(Collection<String> values) {
        Set<String> normalized = new TreeSet<>();
        for (String value : values) {
            String literal = requireClean(value, "path literal").trim();
            if (literal.isEmpty()) continue;
            if (!PATH_LITERAL.matcher(literal).matches()) {
                throw new IllegalArgumentException("path literals must be short ASCII route segments");
            }
            normalized.add(literal);
        }
        if (normalized.size() > 128) throw new IllegalArgumentException("at most 128 path literals are allowed");
        return List.copyOf(normalized);
    }

    static String templatePath(String rawPath, Set<String> literals) {
        String path = requireClean(rawPath, "request path");
        if (!path.startsWith("/")) throw new IllegalArgumentException("request path must start with /");
        if (path.equals("/")) return path;
        String[] segments = path.split("/", -1);
        StringBuilder result = new StringBuilder();
        for (int i = 1; i < segments.length; i += 1) {
            result.append('/');
            String segment = segments[i];
            if (segment.isEmpty()) continue;
            result.append(literals.contains(segment) ? segment : "{value}");
            if (result.length() > MAX_PATH_LENGTH) {
                throw new IllegalArgumentException("sanitized request path exceeds 2048 characters");
            }
        }
        return result.toString();
    }

    static boolean pathMatchesPrefix(String path, String prefix) {
        if (prefix.equals("/")) return path.startsWith("/");
        return path.equals(prefix) || path.startsWith(prefix + "/");
    }

    static String safeFieldName(String value) {
        String name = value == null ? "" : value.trim();
        return FIELD_NAME.matcher(name).matches() && !VALUE_LIKE_NAME.matcher(name).matches() ? name : "masked";
    }

    static List<String> headerNames(Collection<String> names) {
        Set<String> result = new TreeSet<>();
        for (String value : names) {
            String name = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
            result.add(HEADER_NAME.matcher(name).matches() && !VALUE_LIKE_NAME.matcher(name).matches()
                    ? name : "x-masked");
        }
        return List.copyOf(result);
    }

    static String httpMethod(String value) {
        String method = value == null ? "" : value.toUpperCase(Locale.ROOT);
        return method.matches("[!#$%&'*+.^_`|~0-9A-Z-]{1,32}") ? method : "UNKNOWN";
    }

    static String httpVersion(String value) {
        if (value == null) return "UNKNOWN";
        String version = value.toUpperCase(Locale.ROOT);
        return version.matches("HTTP/(?:[0-9]+(?:\\.[0-9]+)?|2|3)") ? version : "UNKNOWN";
    }

    static String mediaType(String value) {
        if (value == null) return null;
        String mediaType = value.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
        return mediaType.matches("[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+") ? mediaType : null;
    }

    static String byteBucket(int bytes) {
        if (bytes == 0) return "EMPTY";
        if (bytes <= 1024) return "LE_1_KIB";
        if (bytes <= 4096) return "LE_4_KIB";
        if (bytes <= 16384) return "LE_16_KIB";
        if (bytes <= 65536) return "LE_64_KIB";
        if (bytes <= 262144) return "LE_256_KIB";
        if (bytes <= 1048576) return "LE_1_MIB";
        return "OVER_1_MIB";
    }

    static int representativeBodySize(int bytes) {
        return switch (byteBucket(bytes)) {
            case "EMPTY" -> 0;
            case "LE_1_KIB" -> 1024;
            case "LE_4_KIB" -> 4096;
            case "LE_16_KIB" -> 16384;
            case "LE_64_KIB" -> 65536;
            case "LE_256_KIB" -> 262144;
            case "LE_1_MIB" -> 1048576;
            default -> 1048577;
        };
    }

    static List<String> commaSeparatedLiterals(String value) {
        List<String> values = new ArrayList<>();
        if (value != null) {
            for (String part : value.split(",", -1)) values.add(part);
        }
        return normalizePathLiterals(values);
    }

    private static String requireClean(String value, String label) {
        if (value == null) throw new IllegalArgumentException(label + " is required");
        for (int i = 0; i < value.length(); i += 1) {
            char character = value.charAt(i);
            if (Character.isISOControl(character) || character == '\u2028' || character == '\u2029') {
                throw new IllegalArgumentException(label + " contains a control character");
            }
        }
        return value;
    }
}

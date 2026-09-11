package dev.lastaperture.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.format.DateTimeFormatter;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class ProxyHistoryExporter {
    private static final int MAX_HEADER_NAMES = 512;
    private static final int MAX_COOKIE_NAMES = 512;
    private static final int MAX_QUERY_NAMES = 512;
    private static final int MAX_BODY_FIELDS = 1024;
    private static final int MAX_AGGREGATE_METADATA_WEIGHT = 90_000;
    private final MontoyaApi api;
    private final BurpRuntime runtime;

    ProxyHistoryExporter(MontoyaApi api, BurpRuntime runtime) {
        this.api = api;
        this.runtime = runtime;
    }

    ExportSummary export(ExportConfiguration configuration) throws IOException {
        ensureRunning();
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        int historyRecordsAvailable = history.size();
        int historyRecordsExamined = Math.min(historyRecordsAvailable, configuration.maxItems());
        List<ProxyHttpRequestResponse> selected = new ArrayList<>(historyRecordsExamined);
        for (int index = 0; index < historyRecordsExamined; index += 1) {
            ensureRunning();
            selected.add(history.get(index));
        }
        selected.sort(Comparator
                .comparing(ProxyHttpRequestResponse::time)
                .thenComparingInt(ProxyHttpRequestResponse::id));

        List<Map<String, Object>> entries = new ArrayList<>();
        int offScope = 0;
        int malformed = 0;
        int limitOmitted = historyRecordsAvailable - historyRecordsExamined;
        int aggregateMetadataWeight = 0;
        for (ProxyHttpRequestResponse item : selected) {
            ensureRunning();
            try {
                HttpRequest request = item.finalRequest();
                String origin = originOf(request.httpService());
                String path = request.pathWithoutQuery();
                if (!origin.equals(configuration.origin())
                        || !CaptureSanitizer.pathMatchesPrefix(path, configuration.pathPrefix())) {
                    offScope += 1;
                    continue;
                }
                HarEntry entry = entryJson(item, request, configuration.pathLiteralSet());
                if (aggregateMetadataWeight + entry.metadataWeight() > MAX_AGGREGATE_METADATA_WEIGHT) {
                    limitOmitted += 1;
                    continue;
                }
                entries.add(entry.value());
                aggregateMetadataWeight += entry.metadataWeight();
            } catch (RuntimeException error) {
                malformed += 1;
            }
        }

        Map<String, Object> har = harJson(
                configuration,
                entries,
                historyRecordsAvailable,
                historyRecordsExamined,
                offScope,
                malformed,
                limitOmitted);
        ensureRunning();
        writeExclusive(configuration.output(), CanonicalJson.encode(har) + "\n");
        return new ExportSummary(entries.size(), offScope, malformed, limitOmitted, configuration.output());
    }

    private Map<String, Object> harJson(
            ExportConfiguration configuration,
            List<Map<String, Object>> entries,
            int historyRecordsAvailable,
            int historyRecordsExamined,
            int offScope,
            int malformed,
            int limitOmitted) {
        Map<String, Object> capabilities = new LinkedHashMap<>();
        capabilities.put("active_scanner", "NOT_USED");
        capabilities.put("history_export", "AVAILABLE");
        capabilities.put("network_dispatch", "DISABLED");
        capabilities.put("proxy_history", "AVAILABLE");
        capabilities.put("traffic_modification", "DISABLED");

        Map<String, Object> scope = new LinkedHashMap<>();
        scope.put("origin", configuration.origin());
        scope.put("path_literals", configuration.pathLiterals());
        scope.put("path_prefix_template", CaptureSanitizer.templatePath(
                configuration.pathPrefix(), configuration.pathLiteralSet()));

        Map<String, Object> limits = new LinkedHashMap<>();
        limits.put("history_records_available", historyRecordsAvailable);
        limits.put("history_records_examined", historyRecordsExamined);
        limits.put("max_items", configuration.maxItems());
        Map<String, Object> redaction = new LinkedHashMap<>();
        redaction.put("body_values_removed", true);
        redaction.put("cookie_values_removed", true);
        redaction.put("header_values_removed_except_content_type", true);
        redaction.put("path_values_removed_unless_operator_marked_literal", true);
        redaction.put("query_values_removed", true);
        redaction.put("structural_content_type_retained", true);
        redaction.put("unsafe_names_masked", true);

        Map<String, Object> skipped = new LinkedHashMap<>();
        skipped.put("limit", limitOmitted);
        skipped.put("malformed", malformed);
        skipped.put("off_scope", offScope);

        Map<String, Object> provenance = new LinkedHashMap<>();
        provenance.put("applied_to_audit_bundle", false);
        provenance.put("capabilities", capabilities);
        provenance.put("capture_protocol", "burp-montoya-sanitized-har-v1");
        provenance.put("core_evidence_provenance", "WEB_HAR");
        provenance.put("limits", limits);
        provenance.put("redaction", redaction);
        provenance.put("scope", scope);
        provenance.put("security_verdict", "NOT_ASSESSED");
        provenance.put("skipped", skipped);
        provenance.put("source", runtime.sourceJson());

        Map<String, Object> creator = new LinkedHashMap<>();
        creator.put("name", "The Last Aperture Burp Montoya Export");
        creator.put("version", "1.0.0");

        Map<String, Object> log = new LinkedHashMap<>();
        log.put("_lastAperture", provenance);
        log.put("creator", creator);
        log.put("entries", entries);
        log.put("version", "1.2");
        return Map.of("log", log);
    }

    private HarEntry entryJson(
            ProxyHttpRequestResponse item,
            HttpRequest request,
            Set<String> pathLiterals) {
        HarRequest harRequest = requestJson(request, pathLiterals);
        HarResponse harResponse = item.hasResponse() ? responseJson(item.originalResponse()) : emptyResponse();
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("_lastAperture", Map.of(
                "edited", item.edited(),
                "history_id", item.id(),
                "listener_port", item.listenerPort(),
                "metadata_truncated", harRequest.truncated() || harResponse.truncated()));
        entry.put("cache", Map.of());
        entry.put("request", harRequest.value());
        entry.put("response", harResponse.value());
        entry.put("startedDateTime", DateTimeFormatter.ISO_INSTANT.format(item.time().toInstant()));
        entry.put("time", 0);
        entry.put("timings", Map.of("receive", 0, "send", 0, "wait", 0));
        int metadataWeight = 1 + harRequest.queryNames()
                + 2 * (harRequest.headerNames() + harRequest.cookieNames() + harRequest.bodyFields()
                + harResponse.headerNames() + harResponse.cookieNames());
        return new HarEntry(entry, metadataWeight);
    }

    private HarRequest requestJson(HttpRequest request, Set<String> pathLiterals) {
        List<ParsedHttpParameter> parameters = new ArrayList<>(request.parameters());
        Bounded<String> queryNames = namesFor(parameters, Set.of(HttpParameterType.URL), MAX_QUERY_NAMES);
        Bounded<String> cookieNames = namesFor(parameters, Set.of(HttpParameterType.COOKIE), MAX_COOKIE_NAMES);
        Bounded<Map<String, Object>> bodyFields = bodyFields(parameters);
        Bounded<String> headerNames = bounded(CaptureSanitizer.headerNames(
                request.headers().stream().map(HttpHeader::name).toList()), MAX_HEADER_NAMES);
        String contentType = CaptureSanitizer.mediaType(request.headerValue("Content-Type"));
        String template = CaptureSanitizer.templatePath(request.pathWithoutQuery(), pathLiterals);
        int representativeBodySize = CaptureSanitizer.representativeBodySize(request.body().length());

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("bodySize", representativeBodySize);
        result.put("cookies", harNames(cookieNames.values()));
        result.put("headers", harHeaders(headerNames.values(), contentType));
        result.put("headersSize", -1);
        result.put("httpVersion", CaptureSanitizer.httpVersion(request.httpVersion()));
        result.put("method", CaptureSanitizer.httpMethod(request.method()));
        Map<String, Object> postData = harPostData(contentType, bodyFields.values(), representativeBodySize);
        if (postData != null) result.put("postData", postData);
        result.put("queryString", harNames(queryNames.values()));
        result.put("url", sanitizedUrl(originOf(request.httpService()), template, queryNames.values()));
        boolean truncated = queryNames.truncated() || cookieNames.truncated()
                || bodyFields.truncated() || headerNames.truncated();
        return new HarRequest(result, queryNames.values().size(), headerNames.values().size(),
                cookieNames.values().size(), bodyFields.values().size(), truncated);
    }

    private HarResponse responseJson(HttpResponse response) {
        Bounded<String> headerNames = bounded(CaptureSanitizer.headerNames(
                response.headers().stream().map(HttpHeader::name).toList()), MAX_HEADER_NAMES);
        Bounded<String> cookieNames = bounded(response.cookies().stream()
                .map(Cookie::name)
                .map(CaptureSanitizer::safeFieldName)
                .distinct()
                .sorted()
                .toList(), MAX_COOKIE_NAMES);
        String contentType = CaptureSanitizer.mediaType(response.headerValue("Content-Type"));
        Map<String, Object> content = new LinkedHashMap<>();
        content.put("mimeType", contentType == null ? "" : contentType);
        content.put("size", CaptureSanitizer.representativeBodySize(response.body().length()));

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("bodySize", CaptureSanitizer.representativeBodySize(response.body().length()));
        result.put("content", content);
        result.put("cookies", harNames(cookieNames.values()));
        result.put("headers", harHeaders(headerNames.values(), contentType));
        result.put("headersSize", -1);
        result.put("httpVersion", CaptureSanitizer.httpVersion(response.httpVersion()));
        result.put("redirectURL", "");
        result.put("status", (int) response.statusCode());
        result.put("statusText", "");
        return new HarResponse(result, headerNames.values().size(), cookieNames.values().size(),
                headerNames.truncated() || cookieNames.truncated());
    }

    private static HarResponse emptyResponse() {
        Map<String, Object> content = new LinkedHashMap<>();
        content.put("mimeType", "");
        content.put("size", 0);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("bodySize", 0);
        response.put("content", content);
        response.put("cookies", List.of());
        response.put("headers", List.of());
        response.put("headersSize", -1);
        response.put("httpVersion", "UNKNOWN");
        response.put("redirectURL", "");
        response.put("status", 0);
        response.put("statusText", "");
        return new HarResponse(response, 0, 0, false);
    }

    private static Bounded<Map<String, Object>> bodyFields(List<ParsedHttpParameter> parameters) {
        List<Map<String, Object>> fields = new ArrayList<>();
        for (ParsedHttpParameter parameter : parameters) {
            if (parameter.type() == HttpParameterType.URL || parameter.type() == HttpParameterType.COOKIE) continue;
            Map<String, Object> field = new LinkedHashMap<>();
            field.put("kind", parameter.type().name());
            field.put("name", CaptureSanitizer.safeFieldName(parameter.name()));
            fields.add(field);
        }
        fields.sort(Comparator
                .comparing((Map<String, Object> field) -> String.valueOf(field.get("kind")))
                .thenComparing(field -> String.valueOf(field.get("name"))));
        return bounded(fields, MAX_BODY_FIELDS);
    }

    private static Bounded<String> namesFor(
            List<ParsedHttpParameter> parameters,
            Set<HttpParameterType> acceptedTypes,
            int limit) {
        List<String> names = parameters.stream()
                .filter(parameter -> acceptedTypes.contains(parameter.type()))
                .map(ParsedHttpParameter::name)
                .map(CaptureSanitizer::safeFieldName)
                .distinct()
                .sorted()
                .toList();
        return bounded(names, limit);
    }

    private static <T> Bounded<T> bounded(List<T> values, int limit) {
        return values.size() <= limit
                ? new Bounded<>(List.copyOf(values), false)
                : new Bounded<>(List.copyOf(values.subList(0, limit)), true);
    }

    private static List<Map<String, Object>> harNames(List<String> names) {
        return names.stream().map(name -> {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("name", name);
            item.put("value", "");
            return item;
        }).toList();
    }

    private static List<Map<String, Object>> harHeaders(List<String> names, String contentType) {
        return names.stream().map(name -> {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("name", name);
            item.put("value", name.equals("content-type") && contentType != null ? contentType : "");
            return item;
        }).toList();
    }

    private static Map<String, Object> harPostData(
            String contentType,
            List<Map<String, Object>> fields,
            int representativeBodySize) {
        if (fields.isEmpty() && representativeBodySize == 0) return null;
        boolean parsedJson = fields.stream().anyMatch(field -> field.get("kind").equals(HttpParameterType.JSON.name()));
        boolean parsedForm = fields.stream().anyMatch(field -> field.get("kind").equals(HttpParameterType.BODY.name()));
        boolean parsedMultipart = fields.stream().anyMatch(field -> field.get("kind").equals(HttpParameterType.MULTIPART_ATTRIBUTE.name()));
        boolean json = parsedJson || (contentType != null
                && (contentType.equals("application/json") || contentType.endsWith("+json")));
        boolean form = parsedForm || parsedMultipart || (contentType != null
                && (contentType.equals("application/x-www-form-urlencoded") || contentType.startsWith("multipart/")));
        String effectiveContentType = contentType;
        if (effectiveContentType == null && parsedJson) effectiveContentType = "application/json";
        else if (effectiveContentType == null && parsedMultipart) effectiveContentType = "multipart/form-data";
        else if (effectiveContentType == null && parsedForm) effectiveContentType = "application/x-www-form-urlencoded";
        Map<String, Object> postData = new LinkedHashMap<>();
        postData.put("mimeType", effectiveContentType == null ? "application/octet-stream" : effectiveContentType);
        postData.put("size", representativeBodySize);
        if (json) {
            Map<String, Object> shape = new LinkedHashMap<>();
            for (Map<String, Object> field : fields) shape.put(String.valueOf(field.get("name")), "");
            postData.put("text", CanonicalJson.encode(shape));
        } else if (form) {
            postData.put("params", harNames(fields.stream()
                    .map(field -> String.valueOf(field.get("name"))).distinct().sorted().toList()));
        }
        return postData;
    }

    private static String sanitizedUrl(String origin, String pathTemplate, List<String> queryNames) {
        String path = pathTemplate.replace("{value}", "0");
        if (queryNames.isEmpty()) return origin + path;
        String query = queryNames.stream()
                .map(name -> URLEncoder.encode(name, StandardCharsets.UTF_8) + "=")
                .reduce((left, right) -> left + "&" + right)
                .orElse("");
        return origin + path + "?" + query;
    }

    private static String originOf(HttpService service) {
        String host = service.host();
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
        if (host.contains(":")) host = "[" + host + "]";
        String scheme = service.secure() ? "https" : "http";
        int port = service.port();
        boolean defaultPort = (service.secure() && port == 443) || (!service.secure() && port == 80);
        return CaptureSanitizer.canonicalOrigin(scheme + "://" + host + (defaultPort ? "" : ":" + port));
    }

    private static void writeExclusive(Path output, String content) throws IOException {
        ensureRunning();
        ByteBuffer bytes = StandardCharsets.UTF_8.encode(content);
        try (FileChannel channel = FileChannel.open(
                output,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE)) {
            while (bytes.hasRemaining()) {
                ensureRunning();
                channel.write(bytes);
            }
            channel.force(true);
            ensureRunning();
        }
    }

    private static void ensureRunning() throws InterruptedIOException {
        if (Thread.currentThread().isInterrupted()) {
            throw new InterruptedIOException("Export cancelled because the extension is unloading.");
        }
    }

    record ExportSummary(int exported, int offScope, int malformed, int limitOmitted, Path output) {}
    private record Bounded<T>(List<T> values, boolean truncated) {}
    private record HarEntry(Map<String, Object> value, int metadataWeight) {}
    private record HarRequest(
            Map<String, Object> value,
            int queryNames,
            int headerNames,
            int cookieNames,
            int bodyFields,
            boolean truncated) {}
    private record HarResponse(
            Map<String, Object> value,
            int headerNames,
            int cookieNames,
            boolean truncated) {}
}

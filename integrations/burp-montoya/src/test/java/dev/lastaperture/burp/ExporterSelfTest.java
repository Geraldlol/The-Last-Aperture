package dev.lastaperture.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.io.InterruptedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.AbstractList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/** Local conformance harness. It is compiled only by verify.ps1. */
public final class ExporterSelfTest {
    private static final String SENTINEL = "DO-NOT-EXPORT";

    private ExporterSelfTest() {}

    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 1) throw new IllegalArgumentException("expected one output path");
        Path output = Path.of(arguments[0]).toAbsolutePath();

        HttpService service = mock(HttpService.class, (method, args) -> switch (method.getName()) {
            case "host" -> "service.invalid";
            case "port" -> 443;
            case "secure" -> true;
            default -> unexpected(method);
        });
        List<ParsedHttpParameter> parameters = List.of(
                parameter("tenant", HttpParameterType.URL),
                parameter("SessionId", HttpParameterType.COOKIE),
                parameter("username", HttpParameterType.JSON),
                parameter("password", HttpParameterType.JSON));
        List<HttpHeader> requestHeaders = List.of(
                header("Authorization", "Bearer " + SENTINEL),
                header("Content-Type", "application/json"),
                header("Cookie", "SessionId=" + SENTINEL));
        ByteArray requestBody = bytes(123);
        HttpRequest request = mock(HttpRequest.class, (method, args) -> switch (method.getName()) {
            case "httpService" -> service;
            case "pathWithoutQuery" -> "/api/v1/users/secret-segment";
            case "parameters" -> parameters;
            case "headers" -> requestHeaders;
            case "headerValue" -> "Content-Type".equals(args[0]) ? "application/json" : SENTINEL;
            case "body" -> requestBody;
            case "httpVersion" -> "HTTP/2";
            case "method" -> "POST";
            case "url", "bodyToString", "toByteArray", "toString" -> SENTINEL;
            default -> unexpected(method);
        });

        List<HttpHeader> responseHeaders = List.of(
                header("Content-Type", "application/json"),
                header("Set-Cookie", "SessionId=" + SENTINEL));
        Cookie cookie = mock(Cookie.class, (method, args) -> switch (method.getName()) {
            case "name" -> "SessionId";
            case "value" -> SENTINEL;
            default -> unexpected(method);
        });
        ByteArray responseBody = bytes(2048);
        HttpResponse response = mock(HttpResponse.class, (method, args) -> switch (method.getName()) {
            case "headers" -> responseHeaders;
            case "cookies" -> List.of(cookie);
            case "headerValue" -> "Content-Type".equals(args[0]) ? "application/json" : SENTINEL;
            case "body" -> responseBody;
            case "httpVersion" -> "HTTP/2";
            case "statusCode" -> (short) 200;
            case "bodyToString", "toByteArray", "toString" -> SENTINEL;
            default -> unexpected(method);
        });

        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class, (method, args) -> switch (method.getName()) {
            case "time" -> ZonedDateTime.of(2026, 9, 11, 12, 0, 0, 0, ZoneOffset.UTC);
            case "id" -> 7;
            case "finalRequest" -> request;
            case "request" -> throw new AssertionError("deprecated request() must not be used");
            case "hasResponse" -> true;
            case "originalResponse" -> response;
            case "edited" -> false;
            case "listenerPort" -> 8080;
            default -> unexpected(method);
        });
        HttpRequest formRequest = request(
                service,
                "/api/v1/forms/private-form",
                List.of(parameter("email", HttpParameterType.BODY)),
                List.of(header("Content-Type", "application/x-www-form-urlencoded")),
                "application/x-www-form-urlencoded",
                2048);
        ProxyHttpRequestResponse formItem = item(8, formRequest, response);
        HttpRequest opaqueRequest = request(
                service,
                "/api/v1/uploads/private-upload",
                List.of(),
                List.of(header("Content-Type", "application/octet-stream")),
                "application/octet-stream",
                20_000);
        ProxyHttpRequestResponse opaqueItem = item(9, opaqueRequest, response);
        Proxy burpProxy = mock(Proxy.class, (method, args) -> switch (method.getName()) {
            case "history" -> List.of(item, formItem, opaqueItem);
            default -> unexpected(method);
        });
        MontoyaApi api = mock(MontoyaApi.class, (method, args) -> switch (method.getName()) {
            case "proxy" -> burpProxy;
            default -> unexpected(method);
        });

        ExportConfiguration configuration = new ExportConfiguration(
                "https://service.invalid",
                "/api",
                List.of("api", "v1", "users"),
                10,
                output);
        ProxyHistoryExporter.ExportSummary summary = new ProxyHistoryExporter(
                api,
                new BurpRuntime("Burp Suite Community Edition 2026.8", 1, "COMMUNITY_EDITION"))
                .export(configuration);
        if (summary.exported() != 3) throw new AssertionError("expected three exported items");

        String json = Files.readString(output, StandardCharsets.UTF_8);
        require(json.contains("\"version\":\"1.2\""), "HAR version missing");
        require(json.contains("\"core_evidence_provenance\":\"WEB_HAR\""), "provenance missing");
        require(json.contains("https://service.invalid/api/v1/users/0?tenant="), "sanitized URL missing");
        require(json.contains("\"authorization\""), "header name missing");
        require(json.contains("\\\"password\\\""), "body field name missing");
        require(json.contains("\"mimeType\":\"application/json\",\"size\":1024,\"text\":"),
                "JSON representative body size missing");
        require(json.contains("\"mimeType\":\"application/x-www-form-urlencoded\",\"params\":[{\"name\":\"email\",\"value\":\"\"}],\"size\":4096"),
                "form representative body size missing");
        require(json.contains("\"mimeType\":\"application/octet-stream\",\"size\":65536"),
                "opaque representative body size missing");
        require(!json.contains(SENTINEL), "a protocol value escaped redaction");
        require(!json.contains("secret-segment"), "a path value escaped redaction");

        Path repeatedOutput = output.resolveSibling(output.getFileName() + ".repeated.har");
        ExportConfiguration repeatedConfiguration = new ExportConfiguration(
                "https://service.invalid",
                "/api",
                List.of("api", "v1", "users"),
                10,
                repeatedOutput);
        new ProxyHistoryExporter(api, new BurpRuntime(
                "Burp Suite Community Edition 2026.8", 1, "COMMUNITY_EDITION"))
                .export(repeatedConfiguration);
        require(json.equals(Files.readString(repeatedOutput, StandardCharsets.UTF_8)),
                "identical history did not produce deterministic output");

        AtomicInteger historyReads = new AtomicInteger();
        List<ProxyHttpRequestResponse> boundedHistory = new AbstractList<>() {
            private final List<ProxyHttpRequestResponse> values = List.of(item, formItem, opaqueItem);

            @Override
            public ProxyHttpRequestResponse get(int index) {
                historyReads.incrementAndGet();
                if (index >= values.size()) throw new AssertionError("history traversal exceeded the configured cap");
                return values.get(index);
            }

            @Override
            public int size() {
                return 100;
            }
        };
        Proxy boundedProxy = mock(Proxy.class, (method, args) -> switch (method.getName()) {
            case "history" -> boundedHistory;
            default -> unexpected(method);
        });
        MontoyaApi boundedApi = mock(MontoyaApi.class, (method, args) -> switch (method.getName()) {
            case "proxy" -> boundedProxy;
            default -> unexpected(method);
        });
        Path boundedOutput = output.resolveSibling(output.getFileName() + ".bounded.har");
        ProxyHistoryExporter.ExportSummary boundedSummary = new ProxyHistoryExporter(
                boundedApi,
                new BurpRuntime("Burp Suite Community Edition 2026.8", 1, "COMMUNITY_EDITION"))
                .export(new ExportConfiguration(
                        "https://service.invalid",
                        "/api",
                        List.of("api", "v1", "users"),
                        3,
                        boundedOutput));
        require(historyReads.get() == 3, "history traversal was not bounded by max items");
        require(boundedSummary.limitOmitted() == 97, "unexamined history count was not recorded");
        String boundedJson = Files.readString(boundedOutput, StandardCharsets.UTF_8);
        require(boundedJson.contains("\"history_records_available\":100"), "available history count missing");
        require(boundedJson.contains("\"history_records_examined\":3"), "examined history count missing");

        Path racedOutput = output.resolveSibling(output.getFileName() + ".raced.har");
        ExportConfiguration racedConfiguration = new ExportConfiguration(
                "https://service.invalid",
                "/api",
                List.of("api", "v1", "users"),
                10,
                racedOutput);
        Files.writeString(racedOutput, "RACE-WINNER", StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        try {
            new ProxyHistoryExporter(api, new BurpRuntime(
                    "Burp Suite Community Edition 2026.8", 1, "COMMUNITY_EDITION"))
                    .export(racedConfiguration);
            throw new AssertionError("export replaced a destination created after validation");
        } catch (FileAlreadyExistsException expected) {
            require(Files.readString(racedOutput, StandardCharsets.UTF_8).equals("RACE-WINNER"),
                    "export changed the race winner's file");
        }

        require(CaptureSanitizer.canonicalOrigin("https://[2001:db8::1]:8443")
                        .equals("https://[2001:db8::1]:8443"),
                "IPv6 origin normalization failed");

        Path cancelledOutput = output.resolveSibling(output.getFileName() + ".cancelled.har");
        Thread.currentThread().interrupt();
        try {
            try {
                new ProxyHistoryExporter(api, new BurpRuntime(
                        "Burp Suite Community Edition 2026.8", 1, "COMMUNITY_EDITION"))
                        .export(new ExportConfiguration(
                                "https://service.invalid",
                                "/api",
                                List.of("api", "v1", "users"),
                                10,
                                cancelledOutput));
                throw new AssertionError("interrupted export was not cancelled");
            } catch (InterruptedIOException expected) {
                require(!Files.exists(cancelledOutput), "cancelled export created an output file");
            }
        } finally {
            Thread.interrupted();
        }
    }

    private static ParsedHttpParameter parameter(String name, HttpParameterType type) {
        return mock(ParsedHttpParameter.class, (method, args) -> switch (method.getName()) {
            case "name" -> name;
            case "type" -> type;
            case "value" -> SENTINEL;
            default -> unexpected(method);
        });
    }

    private static HttpRequest request(
            HttpService service,
            String path,
            List<ParsedHttpParameter> parameters,
            List<HttpHeader> headers,
            String contentType,
            int bodyLength) {
        ByteArray body = bytes(bodyLength);
        return mock(HttpRequest.class, (method, args) -> switch (method.getName()) {
            case "httpService" -> service;
            case "pathWithoutQuery" -> path;
            case "parameters" -> parameters;
            case "headers" -> headers;
            case "headerValue" -> "Content-Type".equals(args[0]) ? contentType : SENTINEL;
            case "body" -> body;
            case "httpVersion" -> "HTTP/2";
            case "method" -> "POST";
            case "url", "bodyToString", "toByteArray", "toString" -> SENTINEL;
            default -> unexpected(method);
        });
    }

    private static ProxyHttpRequestResponse item(int id, HttpRequest request, HttpResponse response) {
        return mock(ProxyHttpRequestResponse.class, (method, args) -> switch (method.getName()) {
            case "time" -> ZonedDateTime.of(2026, 9, 11, 12, 0, id, 0, ZoneOffset.UTC);
            case "id" -> id;
            case "finalRequest" -> request;
            case "request" -> throw new AssertionError("deprecated request() must not be used");
            case "hasResponse" -> true;
            case "originalResponse" -> response;
            case "edited" -> false;
            case "listenerPort" -> 8080;
            default -> unexpected(method);
        });
    }

    private static HttpHeader header(String name, String value) {
        return mock(HttpHeader.class, (method, args) -> switch (method.getName()) {
            case "name" -> name;
            case "value", "toString" -> value;
            default -> unexpected(method);
        });
    }

    private static ByteArray bytes(int length) {
        return mock(ByteArray.class, (method, args) -> switch (method.getName()) {
            case "length" -> length;
            case "getBytes" -> SENTINEL.getBytes(StandardCharsets.UTF_8);
            case "toString" -> SENTINEL;
            default -> unexpected(method);
        });
    }

    @SuppressWarnings("unchecked")
    private static <T> T mock(Class<T> type, Handler handler) {
        InvocationHandler invocation = (proxy, method, args) -> {
            if (method.getDeclaringClass() == Object.class) {
                return switch (method.getName()) {
                    case "toString" -> type.getSimpleName() + "Mock";
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    default -> unexpected(method);
                };
            }
            return handler.invoke(method, args == null ? new Object[0] : args);
        };
        return (T) java.lang.reflect.Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, invocation);
    }

    private static Object unexpected(Method method) {
        throw new AssertionError("unexpected API call: " + method);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    @FunctionalInterface
    private interface Handler {
        Object invoke(Method method, Object[] arguments) throws Throwable;
    }
}
